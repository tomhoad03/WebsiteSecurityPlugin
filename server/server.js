const fs = require("fs");
const {Server} = require("ws");
const wss = new Server({port: 8100});
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
const app = require("express");
const sqlite3 = require("sqlite3");
let database;

// start a connection with the database
let dbServer = app().listen(8110, function () {
    const sqlite3 = require("sqlite3");

    database = new sqlite3.Database("security.db", sqlite3.OPEN_READWRITE, (err) => {
        if (err) {
            console.error(err.message);
        }
        console.log("Connected to the security database.");
    });
});

// start a connection with the plugin
wss.on("connection", ws => {
    console.log("Connected to the plugin.")

    // Listen for messages from the plugin
    ws.on("message", message => {
        const data = JSON.parse(message);

        const serverMsg = "\nHref: " + data.href + "\n"
            + "Domain: " + data.domain + "\n"
            + "Path: " + data.path + "\n";

        console.log(serverMsg);

        let securityTest = {
            domain: data.domain,
            path: data.path,
            score: 0,
            scriptTests: [],
            linkTests: [],
            httpsProtocolsTest: false,
            clientSideCommentsTest: false,
            untrustedLinksTest: true,
            basicXXSTest: false,
            addressAutoFill: data.autoFill1,
            bankingAutoFill: data.autoFill2,
            cookieSecurity: false,
            timelyCookies: false
        }

        // Compute the information from the plugin
        if (data.id === "window") {
            try {
                checkScriptSecurity(data.html);
                checkLinkSecurity(data.html);
                checkInternalScript();

                // CWE-353
                // https://rules.sonarsource.com/html/tag/cwe/RSPEC-5725
                // https://cwe.mitre.org/data/definitions/353.html
                function checkScriptSecurity(html) {
                    if (html.includes("<script")) {
                        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
                        let scriptTest = {
                            href: "null",
                            external: false,
                            nonce: false,
                            integrity: false,
                            crossOrigin: false,
                            eval: false,
                            execScript: false,
                            timeout: false,
                            interval: false,
                            innerHTML: false
                        }

                        // is the referenced script cross-origin anonymous? - there is no exchange of user credentials
                        if (scriptTag.includes("crossorigin=\"anonymous\"")) {
                            scriptTest.crossOrigin = true;
                        }

                        // does the referenced script have integrity? - used to check if the script gets manipulated
                        if (scriptTag.includes("integrity=")) {
                            let integrity = scriptTag.substring(scriptTag.indexOf("integrity=") + 11, scriptTag.indexOf("\"", scriptTag.indexOf("integrity=") + 11))

                            if (integrity.length > 0) {
                                scriptTest.integrity = true;
                            }
                        }

                        // does the referenced script have a nonce? - a cryptographic value to prevent attackers accessing content attributes
                        if (scriptTag.includes("nonce=")) {
                            let nonce = scriptTag.substring(scriptTag.indexOf("nonce=") + 7, scriptTag.indexOf("\"", scriptTag.indexOf("nonce=") + 7))

                            if (nonce.length > 0) {
                                scriptTest.nonce = true;
                            }
                        }

                        // does the external script use http or https protocols?
                        if (scriptTag.includes("src=")) {
                            let scriptSrc = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))
                            scriptTest.href = scriptSrc;

                            if (scriptSrc.includes("http")) {
                                scriptTest.external = true;
                            }

                            let request = new XMLHttpRequest();

                            request.onreadystatechange = function() {
                                if (request.readyState === 4) { // 4 == complete
                                    let response = request.responseText;

                                    // all of these things could allow dynamic execution of code
                                    if (response.includes("eval(")) {
                                        scriptTest.eval = true;
                                    }
                                    if (response.includes("window.execScript")) {
                                        scriptTest.execScript = true;
                                    }
                                    if (response.includes("setTimeout")) {
                                        scriptTest.timeout = true;
                                    }
                                    if (response.includes("setInterval")) {
                                        scriptTest.interval = true;
                                    }
                                    if (response.includes("innerHTML")) {
                                        scriptTest.innerHTML = true;
                                    }
                                }
                            };

                            request.open('GET', scriptSrc);
                            request.send(null);
                        }

                        if (securityTest.scriptTests !== undefined) {
                            securityTest.scriptTests = securityTest.scriptTests.concat(scriptTest);
                        } else {
                            securityTest.scriptTests = [scriptTest];
                        }
                        checkScriptSecurity(html.substring(html.indexOf("</script>") + 9));
                    }
                }

                function checkLinkSecurity(html) {
                    if (html.includes("href=")) {
                        let link = html.substring(html.indexOf("href=\"") + 6, html.indexOf("\"", html.indexOf("href=\"") + 6));
                        let linkTest = {
                            href: link,
                            trusted: false
                        }

                        // return true if is external
                        if (!link.includes("http") || link.includes("https")) {
                            linkTest.trusted = true;
                        } else {
                            securityTest.untrustedLinksTest = false;
                        }

                        if (securityTest.linkTests !== undefined) {
                            securityTest.linkTests = securityTest.linkTests.concat(linkTest);
                        } else {
                            securityTest.linkTests = [linkTest];
                        }
                        checkLinkSecurity(html.substring(html.indexOf("href=\"") + 6));
                    }
                }

                // are any of the scripts internal?
                function checkInternalScript() {
                    for (let scriptTest in securityTest.scriptTests) {
                        if (!scriptTest.external) {
                            break;
                        }
                    }
                    securityTest.score++;
                }

                // does the webpage uses https protocols?
                if (data.protocol === "https:") {
                    securityTest.httpsProtocolsTest = true;
                    securityTest.score++;
                }

                // are any comments are left in the html?
                if (checkClientSideComments(data.html)) {
                    securityTest.clientSideCommentsTest = true;
                    securityTest.score++;
                }

                // CWE-615
                // https://rules.sonarsource.com/html/tag/cwe/RSPEC-1876
                // https://cwe.mitre.org/data/definitions/615.html
                function checkClientSideComments(html) {
                    return !html.includes("<!--") && !html.includes("-->");
                }

                // Performs XSS vulnerability checks.
                securityTest.basicXXSTest = checkBasicXXS();

                function checkBasicXXS() {
                    ws.send(JSON.stringify({
                        id: "xss",
                        message: "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>"
                    }));
                    securityTest.score++;
                    return true;
                }

                // Checks if information is autofilled.
                if (data.autoFill1) {
                    securityTest.score++;
                }
                if (data.autoFill2) {
                    securityTest.score++;
                }
                if (data.safeBrowsing1) {
                    securityTest.score++;
                }
                if (!data.safeBrowsing2) {
                    securityTest.score++;
                }
                if (data.noTracking) {
                    securityTest.score++;
                }
                if (data.auditing) {
                    securityTest.score++;
                }

                // Checks the security of the cookies
                securityTest.cookieSecurity = checkCookieSecurity(data.cookies);
                securityTest.timelyCookies = checkCookieTimeliness(data.cookies);

                function checkCookieSecurity(cookies) {
                    cookies.forEach(cookie => {
                        if (cookie.secure === false) {
                            return false;
                        }
                    });
                    securityTest.score++;
                    return true;
                }

                function checkCookieTimeliness(cookies) {
                    cookies.forEach(cookie => {
                        if (cookie.expirationDate < Math.round(Date.now() / 1000)) {
                            return false;
                        }
                    });
                    securityTest.score++;
                    return true;
                }
            } catch(err) {
                console.error(err);
            }

            /*
            Validates HTML files for compliance against the W3C standards and performs linting to assess code quality against best practices.

            Find missing or unbalanced HTML tags in your documents, stray characters, duplicate IDs, missing or invalid attributes and other recommendations.
            Supports HTML5, SVG 1.1, MathML 3.0, ITS 2.0, RDFa Lite 1.1. Implementation is based on Validator.Nu.

            CORS Policy

            https://securityscorecard.com/blog/common-web-application-vulnerabilities-explained
            https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

            SQL Injection, XSS, insecure cookies, insecure session/session vulnerabilities, insecure file upload, CSRF, internal information/information leakage,
            parameter manipulation, application logic, out of date software, file inclusion, open redirects, brute force

            https://snyk.io/learn/javascript-security/
            https://www.youtube.com/watch?v=mGUsCAWwLGg
             */
        }

        const results = "<ul>" +
            "<li>Domain: " + securityTest.domain + "</li>" +
            "<li>Score: " + securityTest.score + "</li>" +
            "<li>HTTPS Protocols: " + securityTest.httpsProtocolsTest + "</li>" +
            "<li>Client Side Comments: " + securityTest.clientSideCommentsTest + "</li>" +
            "<li>Untrusted Links: " + securityTest.untrustedLinksTest + "</li>" +
            "<li>Basic XSS Test: " + securityTest.basicXXSTest + "</li>" +
            "<li>Address Auto Fill: " + securityTest.addressAutoFill + "</li>" +
            "<li>Banking Auto Fill: " + securityTest.bankingAutoFill + "</li>" +
            "<li>Cookies Security: " + securityTest.cookieSecurity + "</li>" +
            "<li>Timely Cookies: " + securityTest.timelyCookies + "</li>" +
            "</ul>"

        let domainCount = 0;
        const quote = "\'";

        // check if the domain name has already been registered
        database.serialize(() => {
            database.each("SELECT COUNT(*) From Domains WHERE (domainName = " + quote + data.domain + quote + ")", (err, row) => {
                if (err) {
                    console.error(err.message);
                }
                domainCount = Object.values(JSON.parse(JSON.stringify(row)))[0];

                // register a new domain name
                if (domainCount === 0) {
                    database.serialize(() => {
                        database.each("INSERT INTO Domains (domainName) VALUES (" + quote + data.domain + quote + ")", (err, row) => {
                            if (err) {
                                console.error(err.message);
                            }
                            logNewAccess();
                        });
                    });
                } else {
                    logNewAccess();
                }

                // get domainId
                function logNewAccess() {
                    database.serialize(() => {
                        database.each("SELECT domainId FROM Domains WHERE domainName = " + quote + data.domain + quote, (err, row) => {
                            if (err) {
                                console.error(err.message);
                            }
                            let domainId1 = Object.values(JSON.parse(JSON.stringify(row)))[0];
                            console.log("test1");

                            // log new domain name access
                            database.serialize(() => {
                                let domainId;

                                database.run("INSERT INTO DomainEntries (domainId, path, href, score) VALUES (" + quote + domainId1 + quote +
                                                                                                                ", " + quote + data.path + quote +
                                                                                                                ", " + quote + data.href + quote +
                                                                                                                ", " + quote + securityTest.score + quote + ")");

                                // log new script
                                for (let scriptTest in securityTest.scriptTests) {
                                    let script = securityTest.scriptTests[scriptTest];
                                    if (script.href !== "null") {
                                        database.run("INSERT INTO Scripts (href) VALUES (" + quote + script.href + quote + ")");
                                    }
                                }

                                // log new link
                                for (let linkTest in securityTest.linkTests) {
                                    let link = securityTest.linkTests[linkTest];
                                    if (link.href !== "null") {
                                        database.run("INSERT INTO Links (href) VALUES (" + quote + link.href + quote + ")");
                                    }
                                }

                                // database.run("INSERT INTO Links (href) VALUES (" + quote + domainId1 + quote + ")");
                            });

                            console.log("test5");
                        });
                    });
                }
            });
        });

        // update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "results",
            score: securityTest.score,
            results: results
        }));
    })
});

