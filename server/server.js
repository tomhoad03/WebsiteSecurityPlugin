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
        let httpsProtocols, scriptIntegrity;

        // Compute the information from the plugin
        if (data.id === "window") {
            if (data.protocol === "https:") {
                httpsProtocols = true;
                score++;
            }
            if (checkIntegrity(data.html)) {
                scriptIntegrity = true;
                score++;

                /*
                Validates HTML files for compliance against the W3C standards and performs linting to assess code quality against best practices.
                Find missing or unbalanced HTML tags in your documents, stray characters, duplicate IDs, missing or invalid attributes and other recommendations.
                Supports HTML5, SVG 1.1, MathML 3.0, ITS 2.0, RDFa Lite 1.1. Implementation is based on Validator.Nu.
                 */
            }
        }

        const contents = "Domain: " + data.domain + "\n"
                         + "Score: " + score + "\n\n"
                         + "Vulnerabilities\n\n"
                         + "HTTPS Protocols: " + httpsProtocols + "\n"
                         + "Script Integrity: " + scriptIntegrity + "\n";

        fs.writeFileSync(process.cwd() + "\\server\\cache\\websites\\" + data.domain + ".txt", contents);

        // Update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "score",
            score: score
        }));
    })
});

// CWE-353
function checkIntegrity(html) {
    if (html.indexOf("<script") === -1) {
        return true;
    } else {
        let scriptTag = html.substring(html.indexOf("<script"), html.indexOf(">", html.indexOf("<script")) + 1);
        // let scriptInTag = html.substring(html.indexOf(">", html.indexOf("<script")) + 1, html.indexOf("</script>", html.indexOf("<script")));

        if (scriptTag.indexOf("src=") !== -1) {
            let src = scriptTag.substring(scriptTag.indexOf("src=") + 5, scriptTag.indexOf("\"", scriptTag.indexOf("src=") + 5))
            console.log(scriptTag + "\n" + src + "\n");
        }

        return checkIntegrity(html.substring(html.indexOf("</script>") + 9));
    }
}