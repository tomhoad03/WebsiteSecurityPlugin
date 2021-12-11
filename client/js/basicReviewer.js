// Runs when the popup loads
window.addEventListener("DOMContentLoaded", async() => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: basicReview,
    });
});

// Performs a basic code review of the websites
function basicReview() {
    let href = window.location.href; // gets full href
    let domain = window.location.hostname; // host domain (local host for testbed)
    let path = window.location.pathname; // path and filename of the current page
    let protocol = window.location.protocol; // http or https

    let ws = new WebSocket("ws://localhost:8080");

    ws.addEventListener("open", wss => {
        console.log("We are connected.");

        ws.send(JSON.stringify({
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol
        }));

    });

    ws.addEventListener("message", message => {
        console.log(message.data);
    });
}