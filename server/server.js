const fs = require("fs");
const WebSocket = require("ws");
const wss = new WebSocket.Server({port: 8080});

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
        let httpsProtocols = false, scriptIntegrity = false, clientSideComments = false;

        // Compute the information from the plugin
        if (data.id === "window") {

            // Check if the webpage uses https protocols
            if (data.protocol === "https:") {
                httpsProtocols = true;
                score++;
            }

            // Check if external scripts are secure
            if (checkScriptIntegrity(data.html)) {
                scriptIntegrity = true;
                score++;
            }

            // Check if any comments are left in the html
            if (checkClientSideComments(data.html)) {
                clientSideComments = true;
                score++;
            }
            /*
            Validates HTML files for compliance against the W3C standards and performs linting to assess code quality against best practices.
            Find missing or unbalanced HTML tags in your documents, stray characters, duplicate IDs, missing or invalid attributes and other recommendations.
            Supports HTML5, SVG 1.1, MathML 3.0, ITS 2.0, RDFa Lite 1.1. Implementation is based on Validator.Nu.
             */
        }

        const contents = "Domain: " + data.domain + "\n"
                         + "Score: " + score + "\n\n"
                         + "Vulnerabilities\n\n"
                         + "HTTPS Protocols: " + httpsProtocols + "\n"
                         + "Script Integrity: " + scriptIntegrity + "\n"
                         + "Client Side Comments: " + clientSideComments + "\n";

        fs.writeFileSync(process.cwd() + "\\server\\cache\\websites\\" + data.domain + ".txt", contents);

        // Update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "score",
            score: score
        }));
    })
});

// CWE-353
// https://rules.sonarsource.com/html/tag/cwe/RSPEC-5725
// https://cwe.mitre.org/data/definitions/353.html
function checkScriptIntegrity(html) {
    if (!html.includes("<script")) {
        return true;
    } else {
        // Get the src and any internal script
        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
        let scriptInTag = html.substring(html.indexOf(">", html.indexOf("<script")) + 1, html.indexOf("</script>", html.indexOf("<script")));
        let src = "", integrity = "";

        // Get src and integrity values
        if (scriptTag.includes("src=")) {
            src = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))
        }
        if (scriptTag.includes("integrity=")) {
            integrity = scriptTag.substring(scriptTag.indexOf("integrity=") + 11, scriptTag.indexOf("\"", scriptTag.indexOf("integrity=") + 11))
        }

        // Return true if script is internal or is external with integrity
        if ((scriptTag.includes("crossorigin=\"anonymous\"") && integrity.length > 0) || !src.includes("http")) {
            return checkScriptIntegrity(html.substring(html.indexOf("</script>") + 9));
        } else {
            return false;
        }
    }
}

// CWE-615
// https://rules.sonarsource.com/html/tag/cwe/RSPEC-1876
// https://cwe.mitre.org/data/definitions/615.html
function checkClientSideComments(html) {
    if (!html.includes("<!--") && !html.includes("-->")) {
        return true;
    }
}