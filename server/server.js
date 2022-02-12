const fs = require("fs");
const {Server} = require("ws");
const wss = new Server({port: 8080});
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;

// Start a connection with the plugin
wss.on("connection", ws => {
    // Listen for messages from the plugin
    ws.on("message", message => {
        const data = JSON.parse(message);

        const serverMsg = "\nHref: " + data.href + "\n"
                          + "Domain: " + data.domain + "\n"
                          + "Path: " + data.path + "\n";
        console.log(serverMsg);

        let securityTest = {
            domain: data.domain,
            score: 0,
            scriptTest: {
                integrityTests: [],
                securityTests: [],
                internalTest: false
            },
            httpsProtocolsTest: false,
            clientSideCommentsTest: false,
            untrustedLinksTest: false,
            basicXXSTest: false,
            addressAutoFill: data.autoFill1,
            bankingAutoFill: data.autoFill2,
            cookieSecurity: false,
            timelyCookies: false
        }

        // Compute the information from the plugin
        if (data.id === "window") {
            try {
                checkScriptIntegrity(data.html);
                checkScriptSecurity(data.html);
                checkInternalScript();

                // CWE-353
                // https://rules.sonarsource.com/html/tag/cwe/RSPEC-5725
                // https://cwe.mitre.org/data/definitions/353.html
                function checkScriptIntegrity(html) {
                    if (html.includes("<script")) {
                        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
                        let scriptIntegrityTest = {
                                external: false,
                                nonce: false,
                                integrity: false,
                                crossOrigin: false
                            }

                        // is the referenced script cross-origin anonymous? - there is no exchange of user credentials
                        if (scriptTag.includes("crossorigin=\"anonymous\"")) {
                            scriptIntegrityTest.crossOrigin = true;
                        }

                        // does the referenced script have integrity? - used to check if the script gets manipulated
                        if (scriptTag.includes("integrity=")) {
                            let integrity = scriptTag.substring(scriptTag.indexOf("integrity=") + 11, scriptTag.indexOf("\"", scriptTag.indexOf("integrity=") + 11))

                            if (integrity.length > 0) {
                                scriptIntegrityTest.integrity = true;
                            }
                        }

                        // does the referenced script have a nonce? - a cryptographic value to prevent attackers accessing content attributes
                        if (scriptTag.includes("nonce=")) {
                            let nonce = scriptTag.substring(scriptTag.indexOf("nonce=") + 7, scriptTag.indexOf("\"", scriptTag.indexOf("nonce=") + 7))

                            if (nonce.length > 0) {
                                scriptIntegrityTest.nonce = true;
                            }
                        }

                        // does the external script use http or https protocols?
                        if (scriptTag.includes("src=")) {
                            let scriptSrc = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))

                            if (scriptSrc.includes("http")) {
                                scriptIntegrityTest.external = true;
                            }
                        }

                        if (securityTest.scriptTest.integrityTests !== undefined) {
                            securityTest.scriptTest.integrityTests = securityTest.scriptTest.integrityTests.concat(scriptIntegrityTest);
                        } else {
                            securityTest.scriptTest.integrityTests = [scriptIntegrityTest];
                        }
                        checkScriptIntegrity(html.substring(html.indexOf("</script>") + 9));
                    }
                }

                function checkScriptSecurity(html) {
                    if (html.includes("<script")) {
                        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
                        let scriptSecurityTest = {
                                eval: false,
                                execScript: false,
                                timeout: false,
                                interval: false,
                                innerHTML: false
                            }

                        if (scriptTag.includes("src=\"")) {
                            let scriptSrc = scriptTag.substring(scriptTag.indexOf("src=\"") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=\"") + 5));
                            let request = new XMLHttpRequest();

                            request.onreadystatechange = function() {
                                if (request.readyState === 4) { // 4 == complete
                                    let response = request.responseText;

                                    // all of these things could allow dynamic execution of code
                                    if (response.includes("eval(")) {
                                        scriptSecurityTest.eval = true;
                                    }
                                    if (response.includes("window.execScript")) {
                                        scriptSecurityTest.execScript = true;
                                    }
                                    if (response.includes("setTimeout")) {
                                        scriptSecurityTest.timeout = true;
                                    }
                                    if (response.includes("setInterval")) {
                                        scriptSecurityTest.interval = true;
                                    }
                                    if (response.includes("innerHTML")) {
                                        scriptSecurityTest.innerHTML = true;
                                    }
                                }
                            };

                            request.open('GET', scriptSrc);
                            request.send(null);
                        }

                        if (securityTest.scriptTest.securityTests !== undefined) {
                            securityTest.scriptTest.securityTests = securityTest.scriptTest.securityTests.concat(scriptSecurityTest);
                        } else {
                            securityTest.scriptTest.securityTests = [scriptSecurityTest];
                        }
                        checkScriptSecurity(html.substring(html.indexOf("</script>") + 9));
                    }
                }

                // are any of the scripts internal?
                function checkInternalScript() {
                    for (let test in securityTest.scriptTest.integrityTests) {
                        if (!test.external) {
                            securityTest.internalTest = true;
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

                // are any hyperlinks on the page suspicious?
                securityTest.untrustedLinksTest = checkUntrustedLinks(data.html);

                function checkUntrustedLinks(html) {
                    if (!html.includes("href=")) {
                        securityTest.score++;
                        return true;
                    } else {
                        let link = html.substring(html.indexOf("href=\"") + 6, html.indexOf("\"", html.indexOf("href=\"") + 6));

                        // return true if is external
                        if (!link.includes("http") || link.includes("https")) {
                            // console.log(link);
                            return checkUntrustedLinks(html.substring(html.indexOf("href=\"") + 6));
                        } else {
                            return false;
                        }
                    }
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
                console.log(err);
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
                            "<li>Script Integrity: " + securityTest.scriptTest.integrityTests + "</li>" +
                            "<li>Script Security: " + securityTest.scriptTest.securityTests + "</li>" +
                            "<li>Internal Scripts: " + securityTest.scriptTest.internalTest + "</li>" +
                            "<li>Client Side Comments: " + securityTest.clientSideCommentsTest + "</li>" +
                            "<li>Untrusted Links: " + securityTest.untrustedLinksTest + "</li>" +
                            "<li>Basic XSS Test: " + securityTest.basicXXSTest + "</li>" +
                            "<li>Address Auto Fill: " + securityTest.addressAutoFill + "</li>" +
                            "<li>Banking Auto Fill: " + securityTest.bankingAutoFill + "</li>" +
                            "<li>Cookies Security: " + securityTest.cookieSecurity + "</li>" +
                            "<li>Timely Cookies: " + securityTest.timelyCookies + "</li>" +
                        "</ul>"

        fs.writeFileSync(process.cwd() + "\\cache\\websites\\" + data.domain + ".txt", results);

        // Update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "results",
            score: securityTest.score,
            results: results
        }));
    })
});