const fs = require("fs");
const WebSocket = require("ws");
const wss = new WebSocket.Server({port: 8080});

// Start a connection with the plugin
wss.on("connection", ws => {
    // Listen for messages from the plugin
    ws.on("message", message => {
        const data = JSON.parse(message);
        console.log(data);
        let score = 0;

        // Compute the information from the plugin
        if (data.id === "window") {
            if (data.protocol === "https:") {
                score = score + 1;
            }
        }

        // Store a list of secure and insecure websites
        const httpsData = fs.readFileSync(process.cwd() + "/cache/websites/https.txt", "utf8");
        const newHttpsData = httpsData.split("\n").filter(line => line !== data.domain).join("\n");
        fs.writeFileSync(process.cwd() + "/cache/websites/https.txt", newHttpsData);

        const httpData = fs.readFileSync(process.cwd() + "/cache/websites/http.txt", "utf8");
        const newHttpData = httpData.split("\n").filter(line => line !== data.domain).join("\n");
        fs.writeFileSync(process.cwd() + "/cache/websites/http.txt", newHttpData);

        if (score > 0) {
            fs.appendFileSync(process.cwd() + "/cache/websites/https.txt", data.domain + "\n", () => {
                console.log(data.domain + " > /cache/websites/https.txt");
            });
        } else {
            fs.appendFileSync(process.cwd() + "/cache/websites/http.txt", data.domain + "\n", () => {
                console.log(data.domain + " > /cache/websites/http.txt");
            });
        }

        // Update the plugin with the current security rating
        ws.send(JSON.stringify({
            id: "score",
            score: score
        }));
    })
});