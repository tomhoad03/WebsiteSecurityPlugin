const fs = require("fs");
const {Server} = require("ws");
const wss = new Server({port: 8080});

// Start a connection with the plugin
wss.on("connection", ws => {
    // Listen for messages from the plugin
    ws.on("message", message => {
        const data = JSON.parse(message);

        const serverMsg = "\nHref: " + data.href + "\n"
                          + "Domain: " + data.domain + "\n"
                          + "Path: " + data.path + "\n";
        console.log(serverMsg);

        let score = 0;
        let httpsProtocolsTest = false, scriptIntegrityTest = false, clientSideCommentsTest = false, internalScriptTest = false, untrustedLinksTest = false,
            basicXXSTest = false;

        // Compute the information from the plugin
        if (data.id === "window") {

            // Check if the webpage uses https protocols
            if (data.protocol === "https:") {
                httpsProtocolsTest = true;
                score++;
            }

            // Check if external scripts are secure
            if (checkScriptIntegrityTest(data.html)) {
                scriptIntegrityTest = true;
                score++;
            }

            // Check if any internal scripts are used
            if (checkInternalScriptTest(data.html)) {
                internalScriptTest = true;
                score++;
            }

            // Check if any comments are left in the html
            if (checkClientSideCommentsTest(data.html)) {
                clientSideCommentsTest = true;
                score++;
            }

            // Check if any hyperlinks on a page are suspicious.
            if (checkUntrustedLinksTest(data.html)) {
                untrustedLinksTest = true;
                score++;
            }

            // Performs a basic XSS vulnerability check
            if (checkBasicXXSTest(data.html)) {
                ws.send(JSON.stringify({
                    id: "xss",
                    message: "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>"
                }));
                basicXXSTest = true;
                score++;
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
             */
        }

        const results = "<ul>" +
                            "<li>Domain: " + data.domain + "</li>" +
                            "<li>Score: " + score + "</li>" +
                            "<li>HTTPS Protocols: " + httpsProtocolsTest + "</li>" +
                            "<li>Script Integrity: " + scriptIntegrityTest + "</li>" +
                            "<li>Internal Scripts: " + internalScriptTest + "</li>" +
                            "<li>Client Side Comments: " + clientSideCommentsTest + "</li>" +
                            "<li>Untrusted Links: " + untrustedLinksTest + "</li>" +
                            "<li>Basic XSS Test: " + basicXXSTest + "</li>" +
                            "<li>Address Auto Fill: " + data.autoFill1 + "</li>" +
                            "<li>Banking Auto Fill: " + data.autoFill2 + "</li>" +
                        "</ul>"

        fs.writeFileSync(process.cwd() + "\\server\\cache\\websites\\" + data.domain + ".txt", results);

        // Update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "results",
            score: score,
            results: results
        }));
    })
});

// CWE-353
// https://rules.sonarsource.com/html/tag/cwe/RSPEC-5725
// https://cwe.mitre.org/data/definitions/353.html
function checkScriptIntegrityTest(html) {
    if (!html.includes("<script")) {
        return true;
    } else {
        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
        let src = "", integrity = "", nonce = "";

        // Get src and integrity values
        if (scriptTag.includes("src=")) {
            src = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))
        }
        if (scriptTag.includes("integrity=")) {
            integrity = scriptTag.substring(scriptTag.indexOf("integrity=") + 11, scriptTag.indexOf("\"", scriptTag.indexOf("integrity=") + 11))
        }
        if (scriptTag.includes("nonce=")) {
            nonce = scriptTag.substring(scriptTag.indexOf("nonce=") + 7, scriptTag.indexOf("\"", scriptTag.indexOf("nonce=") + 7))
        }

        // Return true if script is internal or is external with integrity
        if ((scriptTag.includes("crossorigin=\"anonymous\"") && integrity.length > 0) || nonce.length > 0 || !src.includes("http")) {
            return checkScriptIntegrityTest(html.substring(html.indexOf("</script>") + 9));
        } else {
            return false;
        }
    }
}

function checkInternalScriptTest(html) {
    if (!html.includes("<script")) {
        return true;
    } else {
        let scriptInTag = html.substring(html.indexOf(">", html.indexOf("<script")) + 1, html.indexOf("</script>", html.indexOf("<script")));

        // Return true if is external
        if (scriptInTag.length === 0) {
            return checkInternalScriptTest(html.substring(html.indexOf("</script>") + 9));
        } else {
            return false;
        }
    }
}

// CWE-615
// https://rules.sonarsource.com/html/tag/cwe/RSPEC-1876
// https://cwe.mitre.org/data/definitions/615.html
function checkClientSideCommentsTest(html) {
    return !html.includes("<!--") && !html.includes("-->");
}

function checkUntrustedLinksTest(html) {
    if (!html.includes("href=")) {
        return true;
    } else {
        let link = html.substring(html.indexOf("href=\"") + 6, html.indexOf("\"", html.indexOf("href=\"") + 6));

        // Return true if is external
        if (!link.includes("http") || link.includes("https")) {
            // console.log(link);
            return checkUntrustedLinksTest(html.substring(html.indexOf("href=\"") + 6));
        } else {
            return false;
        }
    }
}

function checkBasicXXSTest(html) {
    return true;
}