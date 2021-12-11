const WebSocket = require('ws');
const wss = new WebSocket.Server({port: 8080});

let score = 0;

wss.on("connection", ws => {
    console.log("Client connected.")

    ws.on("message", message => {
        const window = JSON.parse(message);
        console.log(window);

        if (window.protocol === "HTTP:") {
            score = 1;
        } else {
            score = 0;
        }

        ws.send("Score: " + score);
    })

    wss.on("close", () => {
        console.log("Client disconnected.");
    })
});