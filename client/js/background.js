let addressAutoFill = false, bankingAutoFill = false, safeBrowsing = false, safeBrowsingReporting = false, doNotTrack = false, hyperlinkAuditing = false;
let cookieData;

// checks if addresses get autofilled
chrome.privacy.services.autofillAddressEnabled.get({}, function(details) {
    if (details.value) {
        addressAutoFill = true;
    }
});

// checks if bank details get autofilled
chrome.privacy.services.autofillCreditCardEnabled.get({}, function(details) {
    if (details.value) {
        bankingAutoFill = true;
    }
});

// checks if safe browsing is enabled
chrome.privacy.services.safeBrowsingEnabled.get({}, function(details) {
    if (details.value) {
        safeBrowsing = true;
    }
});

// checks if safe browsing blocks a page
chrome.privacy.services.safeBrowsingReportingEnabled.get({}, function(details) {
    if (details.value) {
        safeBrowsingReporting = true;
    }
});

// checks if chrome allows 'do not track'
chrome.privacy.services.doNotTrackEnabled.get({}, function(details) {
    if (details.value) {
        doNotTrack = true;
    }
});

// checks if chrome audit pings hyperlinks
chrome.privacy.services.hyperlinkAuditingEnabled.get({}, function(details) {
    if (details.value) {
        hyperlinkAuditing = true;
    }
});

// gets all the cookies stored on the browser
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

// Everytime the user changes tabs, relay the new information to the server
chrome.tabs.onActivated.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
        args: [addressAutoFill, bankingAutoFill, cookieData]
    });
})

function socket(addressAutoFill, bankingAutoFill, cookieData) {
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
            safeBrowsing1: safeBrowsing,
            safeBrowsing2: safeBrowsingReporting,
            noTracking: doNotTrack,
            auditing: hyperlinkAuditing,
            cookies: cookieData.filter(cookie => cookie.domain.includes(window.location.hostname)),
            html: document.getElementsByTagName('html')[0].innerHTML,
        }));
    });

    ws.addEventListener("message", message => {
        const data = JSON.parse(message.data);

        // update the security score
        if (data.id === "results") {
            let results = data.results;
            chrome.storage.sync.set({results});

        // perform XSS checks
        } else if (data.id === "xss") {
            try {
                let input = document.getElementById("enterName"); // ! change to look for all input boxes !
                input.value = data.message;
            } catch (err) {
                console.log("no inputs");
            }
        }
    });
}

// ad blocker - manifest v2 version
/*
chrome.declarativeNetRequest.onBeforeRequest.addListener(function(details) {
        return {
            cancel: true
        }
    },
    {urls: ["*://*.zedo.com/*"]},
    ["blocking"]
);*/
