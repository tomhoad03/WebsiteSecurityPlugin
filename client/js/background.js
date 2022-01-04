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
        console.log("We are connected.");

        ws.send(JSON.stringify({
            id: "window",
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol,
            html: document.getElementsByTagName('html')[0].innerHTML
        }));
    });

    // Update the security score.
    ws.addEventListener("message", message => {
        const data = JSON.parse(message.data);
        console.log(data);

        if (data.id === "score") {
            let score = data.score;
            console.log("Score = " + score);
            chrome.storage.sync.set({score});
        }
    });
}
