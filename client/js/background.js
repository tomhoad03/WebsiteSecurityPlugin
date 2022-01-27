chrome.webNavigation.onDOMContentLoaded.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
    });
});

function socket() {
    let ws = new WebSocket("ws://localhost:8080");

    // Listen for messages from the server.
    ws.addEventListener("open", () => {
        ws.send(JSON.stringify({
            id: "window",
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol,
            html: document.getElementsByTagName('html')[0].innerHTML,
        }));
    });

    // Update the security score.
    ws.addEventListener("message", message => {
        const data = JSON.parse(message.data);

        if (data.id === "results") {
            let results = data.results;
            chrome.storage.sync.set({results});
        }
    });

    // Perform XSS checks.
    ws.addEventListener("xss", message => {
    });
}
