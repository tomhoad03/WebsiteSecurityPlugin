// Runs when the popup loads
window.addEventListener("DOMContentLoaded", async() => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: basicReview,
    });
});

// Performs a basic code review of the websites
function basicReview() {
    let ws = new WebSocket("ws://localhost:8080");

    ws.addEventListener("open", wss => {
        console.log("We are connected.");

        ws.send(JSON.stringify({
            id: "window",
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol
        }));
    });

    ws.addEventListener("message", message => {
        const data = JSON.parse(message.data);
        console.log(data);

        if (data.id === "score") {
            console.log("Score = " + data.score);
        }
    });
}