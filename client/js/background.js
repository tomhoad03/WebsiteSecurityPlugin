let addressAutoFill = false, bankingAutoFill = false;
let cookieData;

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

chrome.cookies.getAll({}, function(details) {
    cookieData = details;
});

// Everytime the webpage reloads, relay the new information to the server
chrome.webNavigation.onDOMContentLoaded.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
        args: [addressAutoFill, bankingAutoFill, cookieData]
    });
});

function socket(addressAutoFill, bankingAutoFill, cookieData) {
    let ws = new WebSocket("ws://localhost:8080");

    console.log(cookieData.filter(cookie => cookie.domain.includes(window.location.hostname)));

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

    ws.addEventListener("message", message => {
        const data = JSON.parse(message.data);

        // Update the security score.
        if (data.id === "results") {
            let results = data.results;
            chrome.storage.sync.set({results});

        // Perform XSS checks.
        } else if (data.id === "xss") {
            let input = document.getElementById("enterName");
            input.value = data.message;
        }
    });
}
