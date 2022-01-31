let addressAutoFill = false, bankingAutoFill = false;

chrome.privacy.services.autofillAddressEnabled.get({}, function(details) {
    if (details.value) {
        addressAutoFill = true;
    }
});

chrome.privacy.services.autofillCreditCardEnabled.get({}, function(details) {
    if (details.value) {
        bankingAutoFill = true;
    }
});

// Everytime the webpage reloads, relay the new information to the server
chrome.webNavigation.onDOMContentLoaded.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
        args: [addressAutoFill, bankingAutoFill]
    });
});

function socket(addressAutoFill, bankingAutoFill) {
    let ws = new WebSocket("ws://localhost:8080");

    // Listen for messages from the server.
    ws.addEventListener("open", () => {
        ws.send(JSON.stringify({
            id: "window",
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol,
            autoFill1: addressAutoFill,
            autoFill2: bankingAutoFill,
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
