const {Server} = require("ws");
const wss = new Server({port: 8100});
const XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
const app = require("express");
let database;

// start a connection with the database
app().listen(8110, function () {
    const sqlite3 = require("sqlite3");

    database = new sqlite3.Database("server\\security.db", sqlite3.OPEN_READWRITE, (err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log("Connected to the security database.");
        }
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
            href: data.href,
            path: data.path,
            score: 0,
            maxScore: 28,
            scriptTests: [],
            externalScriptsTest: false,
            crossOriginScriptsTest: false,
            integrityScriptsTest: false,
            nonceScriptsTest: false,
            dynamicExecutionScriptsTest: false,
            outdatedScriptsTest: false,
            linkTests: [],
            trustedLinksTest: false,
            httpsProtocolsTest: false, // http or https?
            clientSideCommentsTest: false, // comments?
            addressAutoFillTest: false, // address autofill
            bankingAutoFillTest: false, // banking autofill
            safeBrowsingTest: false, // safe browsing enabled
            browsingBlockingTest: false, // safe browsing blocking enabled
            trackingTest: false, // tracking prevention
            auditingTest: false, // link auditing
            cookieSecurityTest: false, // secure cookies?
            timelyCookiesTest: false, // timely cookies
            googleSafeBrowsingTest: false, // safe browsing api result
            ipQualityUnsafeTest: false, // ip quality api results
            ipQualityDnsValidTest: false,
            ipQualitySpammingTest: false,
            ipQualityMalwareTest: false,
            ipQualityPhishingTest: false,
            ipQualitySuspiciousTest: false,
            ipQualityAdultTest: false,
            ipQualityRiskScore: 0
        }

        // Compute the information from the plugin
        if (data.id === "window") {
            try {
                checkScriptSecurity(data.html, 0);
                function checkScriptSecurity(html, count) {
                    let numberScripts = 0, crossOriginScripts = 0, integrityScripts = 0, nonceScripts = 0, externalScripts = 0, dynamicExecutionScripts = 0;

                    if (html.includes("<script")) {
                        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
                        let scriptTest = {
                            href: "null",
                            crossOrigin: false,
                            integrity: false,
                            nonce: false,
                            external: false,
                            dynamicExecutionScript: false,
                            outdated: false
                        }
                        numberScripts++;

                        // is the referenced script cross-origin anonymous? - there is no exchange of user credentials
                        if (scriptTag.includes("crossorigin=\"anonymous\"")) {
                            scriptTest.crossOrigin = true;
                            crossOriginScripts++;
                        }

                        // does the referenced script have integrity? - used to check if the script gets manipulated
                        if (scriptTag.includes("integrity=")) {
                            let integrity = scriptTag.substring(scriptTag.indexOf("integrity=") + 11, scriptTag.indexOf("\"", scriptTag.indexOf("integrity=") + 11))

                            if (integrity.length > 0) {
                                scriptTest.integrity = true;
                                integrityScripts++;
                            }
                        }

                        // does the referenced script have a nonce? - a cryptographic value to prevent attackers accessing content attributes
                        if (scriptTag.includes("nonce=")) {
                            let nonce = scriptTag.substring(scriptTag.indexOf("nonce=") + 7, scriptTag.indexOf("\"", scriptTag.indexOf("nonce=") + 7))

                            if (nonce.length > 0) {
                                scriptTest.nonce = true;
                                nonceScripts++;
                            }
                        }

                        // does the external script use http or https protocols?
                        if (scriptTag.includes("src=")) {
                            let scriptSrc = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))
                            scriptTest.href = scriptSrc;

                            if (scriptSrc.includes("http")) {
                                scriptTest.external = true;
                                externalScripts++;
                            }

                            let request = new XMLHttpRequest();

                            request.onreadystatechange = function () {
                                if (request.readyState === 4) { // 4 == complete
                                    let response = request.responseText;

                                    // all of these things could allow dynamic execution of code
                                    if (response.includes("eval(") ||
                                        response.includes("window.execScript") ||
                                        response.includes("window.execScript") ||
                                        response.includes("setInterval") ||
                                        response.includes("innerHTML")){
                                        scriptTest.dynamicExecutionScript = true;
                                        dynamicExecutionScripts++;
                                    }
                                }
                            };

                            request.open('GET', scriptSrc);
                            request.send(null);
                        }

                        // is the script outdated - only works for jquery
                        if (scriptTag.includes("jquery")) {
                            let splitVersion = scriptTag.substring(scriptTag.indexOf("jquery-") + 7, scriptTag.indexOf(".js", scriptTag.indexOf("jquery-") + 7)).split(".");

                            if (parseInt(splitVersion[0]) < 3 || parseInt(splitVersion[1]) < 6 || parseInt(splitVersion[2]) < 0) {
                                if (!securityTest.outdatedScriptsTest) {
                                    securityTest.outdatedScriptsTest = true;
                                    securityTest.score++;
                                }
                            }
                        }

                        if (securityTest.scriptTests !== undefined) {
                            securityTest.scriptTests = securityTest.scriptTests.concat(scriptTest);
                        } else {
                            securityTest.scriptTests = [scriptTest];
                        }
                        checkScriptSecurity(html.substring(html.indexOf("</script>") + 9), count + 1);
                    } else {
                        if (numberScripts > crossOriginScripts) {
                            securityTest.crossOriginScriptsTest = true;
                            securityTest.score++;
                        }
                        if (numberScripts > integrityScripts) {
                            securityTest.integrityScriptsTest = true;
                            securityTest.score++;
                        }
                        if (numberScripts > nonceScripts) {
                            securityTest.nonceScriptsTest = true;
                            securityTest.score++;
                        }
                        if (numberScripts > externalScripts) {
                            securityTest.externalScriptsTest = true;
                            securityTest.score++;
                        }
                        if (numberScripts > dynamicExecutionScripts) {
                            securityTest.dynamicExecutionScriptsTest = true;
                            securityTest.score++;
                        }
                    }
                }

                checkLinkSecurity(data.html, 0);
                function checkLinkSecurity(html, count) {
                    let numberLinks = 0, trustedLinks = 0;

                    if (html.includes("href=") && count < 10000) {
                        let link = html.substring(html.indexOf("href=\"") + 6, html.indexOf("\"", html.indexOf("href=\"") + 6));
                        let linkTest = {
                            href: link,
                            trusted: false
                        }
                        numberLinks++;

                        if (!link.includes("http") || link.includes("https")) {
                            linkTest.trusted = true;
                            trustedLinks++;
                        }

                        if (securityTest.linkTests !== undefined) {
                            securityTest.linkTests = securityTest.linkTests.concat(linkTest);
                        } else {
                            securityTest.linkTests = [linkTest];
                        }
                        checkLinkSecurity(html.substring(html.indexOf("href=\"") + 6), count + 1);
                    } else {
                        if (numberLinks > trustedLinks) {
                            securityTest.trustedLinksTest = true;
                            securityTest.score++;
                        }
                    }
                }

                // does the webpage uses https protocols?
                if (data.protocol === "https:") {
                    securityTest.httpsProtocolsTest = true;
                    securityTest.score++;
                }
                // are any comments are left in the html?
                if (!data.html.includes("<!--") && !data.html.includes("-->")) {
                    securityTest.clientSideCommentsTest = true;
                    securityTest.score++;
                }
                // checks browser properties
                if (data.addressAutoFill) {
                    securityTest.addressAutoFillTest = data.addressAutoFill;
                    securityTest.score++;
                }
                if (data.bankingAutoFill) {
                    securityTest.bankingAutoFillTest = data.bankingAutoFill;
                    securityTest.score++;
                }
                if (data.safeBrowsing) {
                    securityTest.safeBrowsing1Test = data.safeBrowsing;
                    securityTest.score++;
                }
                if (!data.browsingBlocking) {
                    securityTest.browsingBlockingTest = data.browsingBlocking;
                    securityTest.score++;
                }
                if (data.tracking) {
                    securityTest.trackingTest = data.tracking;
                    securityTest.score++;
                }
                if (data.auditing) {
                    securityTest.auditingTest = data.auditing;
                    securityTest.score++;
                }

                // Checks the security of the cookies
                securityTest.cookieSecurityTest = checkCookieSecurity(data.cookies);
                securityTest.timelyCookiesTest = checkCookieTimeliness(data.cookies);

                function checkCookieSecurity(cookies) {
                    let secureCookies = true;

                    cookies.forEach(cookie => {
                        if (cookie.secure === false) {
                            secureCookies = false;
                        }
                    });

                    if (secureCookies) {
                        securityTest.score++;
                    }
                    return secureCookies;
                }

                function checkCookieTimeliness(cookies) {
                    let timelyCookies = true;

                    cookies.forEach(cookie => {
                        if (cookie.expirationDate < Math.round(Date.now() / 1000)) {
                            timelyCookies = false;
                        }
                    });

                    if (timelyCookies) {
                        securityTest.score++;
                    }
                    return timelyCookies;
                }

                // check if google trusts it
                // https://console.cloud.google.com/home/dashboard?project=web-security-plugin
                // AIzaSyApajNfcS7Nr5ukcJapAwok8SXKNLgifec
                checkSafeBrowsingAPI();

                function checkSafeBrowsingAPI() {
                    let safeBrowsingFetch = new XMLHttpRequest();
                    safeBrowsingFetch.onreadystatechange = function () {
                        if (this.readyState === 4 && this.status === 200) {
                            if (this.responseText === "{}\n") {
                                securityTest.googleSafeBrowsingTest = true;
                                securityTest.score++;
                            }
                            checkIPQualityAPI();
                        }
                    };

                    let body = {
                        "client": {
                            "clientId": "tomhoad",
                            "clientVersion": "1.0.0"
                        },
                        "threatInfo": {
                            "threatTypes": ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            "platformTypes": ["WINDOWS"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": data.href}]
                        }
                    }

                    safeBrowsingFetch.open("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyApajNfcS7Nr5ukcJapAwok8SXKNLgifec", true);
                    safeBrowsingFetch.setRequestHeader("Content-type", "application/json");
                    safeBrowsingFetch.send(JSON.stringify(body));
                }

                // https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner
                // YZ3FapTPxtx4zOjHxd263djSQkwUQIBn
                function checkIPQualityAPI() {
                    let qualityFetch = new XMLHttpRequest();
                    qualityFetch.onreadystatechange = function () {
                        if (this.readyState === 4 && this.status === 200) {
                            let result = JSON.parse(this.responseText);

                            securityTest.ipQualityUnsafeTest = result.unsafe;
                            securityTest.ipQualityDnsValidTest = result.dns_valid;
                            securityTest.ipQualitySpammingTest = result.spamming;
                            securityTest.ipQualityMalwareTest = result.malware;
                            securityTest.ipQualityPhishingTest = result.phishing;
                            securityTest.ipQualitySuspiciousTest = result.suspicious;
                            securityTest.ipQualityAdultTest = result.adult;
                            securityTest.ipQualityRiskScoreTest = result.risk_score;

                            if (!securityTest.ipQualityUnsafeTest) { // is the website unsafe? general rating
                                securityTest.score++;
                            }
                            if (securityTest.ipQualityDnsValidTest) { // does the website have valid dns records?
                                securityTest.score++;
                            }
                            if (!securityTest.ipQualitySpammingTest) { // is the website associated with potential spam
                                securityTest.score++;
                            }
                            if (!securityTest.ipQualityMalwareTest) { // is the website associated with malware attacks
                                securityTest.score++;
                            }
                            if (!securityTest.ipQualityPhishingTest) { // is the website associated with phishing attacks
                                securityTest.score++;
                            }
                            if (!securityTest.ipQualitySuspiciousTest) { // is the website associated with malicious attacks
                                securityTest.score++;
                            }
                            if (securityTest.ipQualityAdultTest) { // is the website displaying adult content
                                securityTest.score++;
                            }
                            if (securityTest.ipQualityRiskScore < 100 || (!securityTest.ipQualityMalwareTest && !securityTest.ipQualityPhishingTest)) { // malware or phishing activity detected recently
                                securityTest.score++;

                                if (securityTest.ipQualityRiskScore < 85) { // high risk limit
                                    securityTest.score++;

                                    if (securityTest.ipQualityRiskScore < 75) { // suspicious limit
                                        securityTest.score++;
                                    }
                                }
                            }
                            returnResults();
                        }
                    };

                    let link = "https://ipqualityscore.com/api/json/url/YZ3FapTPxtx4zOjHxd263djSQkwUQIBn/" + encodeURIComponent(data.href);
                    qualityFetch.open("GET", link, true);
                    qualityFetch.setRequestHeader("Content-type", "application/json");
                    qualityFetch.send();
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

                function returnResults() {
                    // update the plugin with the current security rating
                    ws.send(JSON.stringify({
                        id: "results",
                        securityTest: securityTest
                    }));

                    const quote = "\'";

                    // check if the domain name has already been registered
                    database.serialize(() => {
                        database.each("SELECT COUNT(*) From Domains WHERE (domainName = " + quote + securityTest.domain + quote + ")", (err, row) => {
                            if (err) {
                                console.error(err.message);
                            }
                            let domainCount = Object.values(JSON.parse(JSON.stringify(row)))[0];

                            // register a new domain name
                            if (domainCount === 0) {
                                database.each("INSERT INTO Domains (domainName) VALUES (" + quote + securityTest.domain + quote + ")", (err) => {
                                    if (err) {
                                        console.error(err.message);
                                    }
                                    logNewAccess();
                                });
                            } else {
                                logNewAccess();
                            }

                            // get domainId
                            function logNewAccess() {
                                database.serialize(() => {
                                    database.each("SELECT domainId FROM Domains WHERE domainName = " + quote + securityTest.domain + quote, (err, row) => {
                                        if (err) {
                                            console.error(err.message);
                                        }
                                        let domainId1 = Object.values(JSON.parse(JSON.stringify(row)))[0];

                                        // log new domain name access
                                        database.serialize(() => {
                                            let domainEntry = Date.now();

                                            database.run("INSERT INTO DomainEntries (domainEntryId, domainId, path, href, score," +
                                                "crossOriginScriptsTest, integrityScriptsTest, nonceScriptsTest, externalScriptsTest, dynamicExecutionScriptsTest, outdatedScriptsTest, trustedLinksTest, " +
                                                "httpsProtocolsTest, clientSideCommentsTest, addressAutoFillTest, bankingAutoFillTest, safeBrowsingTest, browsingBlockingTest, trackingTest, auditingTest, cookieSecurityTest, timelyCookiesTest," +
                                                "googleSafeBrowsingTest, ipQualityUnsafeTest, ipQualityDnsValidTest, ipQualitySpammingTest, ipQualityMalwareTest, ipQualityPhishingTest, ipQualitySuspiciousTest, ipQualityAdultTest, ipQualityRiskScore)" +
                                                "VALUES (" + quote + domainEntry + quote +
                                                ", " + quote + domainId1 + quote +
                                                ", " + quote + securityTest.path + quote +
                                                ", " + quote + securityTest.href + quote +
                                                ", " + quote + securityTest.score + quote +
                                                ", " + quote + securityTest.crossOriginScriptsTest + quote +
                                                ", " + quote + securityTest.integrityScriptsTest + quote +
                                                ", " + quote + securityTest.nonceScriptsTest + quote +
                                                ", " + quote + securityTest.externalScriptsTest + quote +
                                                ", " + quote + securityTest.dynamicExecutionScriptsTest + quote +
                                                ", " + quote + securityTest.outdatedScriptsTest + quote +
                                                ", " + quote + securityTest.trustedLinksTest + quote +
                                                ", " + quote + securityTest.httpsProtocolsTest + quote +
                                                ", " + quote + securityTest.clientSideCommentsTest + quote +
                                                ", " + quote + securityTest.addressAutoFillTest + quote +
                                                ", " + quote + securityTest.bankingAutoFillTest + quote +
                                                ", " + quote + securityTest.safeBrowsing1Test + quote +
                                                ", " + quote + securityTest.browsingBlockingTest + quote +
                                                ", " + quote + securityTest.trackingTest + quote +
                                                ", " + quote + securityTest.auditingTest + quote +
                                                ", " + quote + securityTest.cookieSecurityTest + quote +
                                                ", " + quote + securityTest.timelyCookiesTest + quote +
                                                ", " + quote + securityTest.googleSafeBrowsingTest + quote +
                                                ", " + quote + securityTest.ipQualityUnsafeTest + quote +
                                                ", " + quote + securityTest.ipQualityDnsValidTest + quote +
                                                ", " + quote + securityTest.ipQualitySpammingTest + quote +
                                                ", " + quote + securityTest.ipQualityMalwareTest + quote +
                                                ", " + quote + securityTest.ipQualityPhishingTest + quote +
                                                ", " + quote + securityTest.ipQualitySuspiciousTest + quote +
                                                ", " + quote + securityTest.ipQualityAdultTest + quote +
                                                ", " + quote + securityTest.ipQualityRiskScore + quote + ")");

                                            // log new script
                                            for (let scriptTest in securityTest.scriptTests) {
                                                let script = securityTest.scriptTests[scriptTest];

                                                if (script.href !== "null") {
                                                    database.each("SELECT COUNT(*) From Scripts WHERE (href = " + quote + script.href + quote + ")", (err, row) => {
                                                        if (err) {
                                                            console.error(err.message);
                                                        }
                                                        let scriptCount = Object.values(JSON.parse(JSON.stringify(row)))[0];

                                                        if (scriptCount === 0) {
                                                            database.run("INSERT INTO Scripts (href, crossOrigin, integrity, nonce, external, dynamicExecutionScript, outdated) VALUES (" + quote + script.href + quote +
                                                                ", " + quote + script.crossOrigin + quote +
                                                                ", " + quote + script.integrity + quote +
                                                                ", " + quote + script.nonce + quote +
                                                                ", " + quote + script.external + quote +
                                                                ", " + quote + script.dynamicExecutionScript + quote +
                                                                ", " + quote + script.outdated + quote + ")");
                                                        }

                                                        database.each("SELECT scriptId FROM Scripts WHERE href = " + quote + script.href + quote, (err, row) => {
                                                            if (err) {
                                                                console.error(err.message);
                                                            }
                                                            let scriptId1 = Object.values(JSON.parse(JSON.stringify(row)))[0];

                                                            database.run("INSERT INTO ScriptEntries (domainEntryId, scriptId) VALUES (" + quote + domainEntry + quote +
                                                                ", " + quote + scriptId1 + quote + ")");
                                                        });
                                                    });
                                                }
                                            }

                                            // log new link
                                            for (let linkTest in securityTest.linkTests) {
                                                let link = securityTest.linkTests[linkTest];

                                                if (link.href !== "null") {
                                                    database.each("SELECT COUNT(*) From Links WHERE (href = " + quote + link.href + quote + ")", (err, row) => {
                                                        if (err) {
                                                            console.error(err.message);
                                                        }
                                                        let linkCount = Object.values(JSON.parse(JSON.stringify(row)))[0];

                                                        if (linkCount === 0) {
                                                            database.run("INSERT INTO Links (href, trusted) VALUES (" + quote + link.href + quote +
                                                                ", " + quote + link.trusted + quote + ")");
                                                        }

                                                        database.each("SELECT linkId FROM Links WHERE href = " + quote + link.href + quote, (err, row) => {
                                                            if (err) {
                                                                console.error(err.message);
                                                            }
                                                            let linkId1 = Object.values(JSON.parse(JSON.stringify(row)))[0];

                                                            database.run("INSERT INTO linkEntries (domainEntryId, linkId) VALUES (" + quote + domainEntry + quote +
                                                                ", " + quote + linkId1 + quote + ")");
                                                        });
                                                    });
                                                }
                                            }
                                        });
                                    });
                                });
                            }
                        });
                    });
                }
            } catch (error) {
                console.log(error);
            }
        }
    })
});

