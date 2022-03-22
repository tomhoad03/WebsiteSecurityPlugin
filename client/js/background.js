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
if (chrome.privacy.services.safeBrowsingEnabled) {
    safeBrowsing = true;
}

// checks if safe browsing blocks a page
if (chrome.privacy.services.safeBrowsingExtendedReportingEnabled) {
    safeBrowsingReporting = true;
}

// checks if chrome allows 'do not track'
if (chrome.privacy.services.doNotTrackEnabled) {
    doNotTrack = true;
}

// checks if chrome audit pings hyperlinks
if (chrome.privacy.services.hyperlinkAuditingEnabled) {
    hyperlinkAuditing = true;
}

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
        args: [addressAutoFill, bankingAutoFill, safeBrowsing, safeBrowsingReporting, doNotTrack, hyperlinkAuditing, cookieData]
    });
});

// Everytime the user changes tabs, relay the new information to the server
chrome.tabs.onActivated.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
        args: [addressAutoFill, bankingAutoFill, safeBrowsing, safeBrowsingReporting, doNotTrack, hyperlinkAuditing, cookieData]
    });
})

function socket(addressAutoFill, bankingAutoFill, safeBrowsing, safeBrowsingReporting, doNotTrack, hyperlinkAuditing, cookieData) {
    let ws = new WebSocket("ws://localhost:8100");

    // Listen for messages from the server.
    ws.onopen = function() {
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
    };

    ws.onmessage = function(message) {
        const data = JSON.parse(message.data);

        // update the security score
        if (data.id === "results") {
            let securityTest1 = data.securityTest;
            chrome.storage.local.set(securityTest1);
            ws.close();
        } else if (data.id === "xss") {
            let inputs = document.getElementsByTagName("input");

            console.log("xss test");
            console.log(inputs);

            for (let input in inputs) {
                input.value = "test";
                console.log(input);
                document.getElementById(input.id).replaceWith(input);
                //input.value = "<script>alert(\"XSS\")</script>"
            }
        }
    };
}

chrome.runtime.onMessage.addListener(
    function(request) {
        if (request.msg === "results_request") {
            chrome.storage.local.get(null, function(securityTest) {
                chrome.runtime.sendMessage({
                    msg: "results_sent",
                    data: {
                        subject: "results",
                        content: securityTest
                    }
                });
            });
        }
    }
);