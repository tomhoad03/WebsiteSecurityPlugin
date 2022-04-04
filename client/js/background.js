let addressAutoFillTest = false, bankingAutoFillTest = false, safeBrowsingTest = false, browsingBlockingTest = false, trackingTest = false, auditingTest = false;
let cookieData;

// checks if addresses get autofilled
chrome.privacy.services.autofillAddressEnabled.get({}, function(details) {
    if (details.value) {
        addressAutoFillTest = true;
    }
});

// checks if bank details get autofilled
chrome.privacy.services.autofillCreditCardEnabled.get({}, function(details) {
    if (details.value) {
        bankingAutoFillTest = true;
    }
});

// checks if safe browsing is enabled
if (chrome.privacy.services.safeBrowsingEnabled) {
    safeBrowsingTest = true;
}

// checks if safe browsing blocks a page
if (chrome.privacy.services.safeBrowsingExtendedReportingEnabled) {
    browsingBlockingTest = true;
}

// checks if chrome allows 'do not track'
if (chrome.privacy.services.doNotTrackEnabled) {
    trackingTest = true;
}

// checks if chrome audit pings hyperlinks
if (chrome.privacy.services.hyperlinkAuditingEnabled) {
    auditingTest = true;
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
        args: [addressAutoFillTest, bankingAutoFillTest, safeBrowsingTest, browsingBlockingTest, trackingTest, auditingTest, cookieData]
    });
});

// Everytime the user changes tabs, relay the new information to the server
chrome.tabs.onActivated.addListener(async () => {
    let [tab] = await chrome.tabs.query({active: true, currentWindow: true});

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: socket,
        args: [addressAutoFillTest, bankingAutoFillTest, safeBrowsingTest, browsingBlockingTest, trackingTest, auditingTest, cookieData]
    });
})

function socket(addressAutoFillTest, bankingAutoFillTest, safeBrowsingTest, browsingBlockingTest, trackingTest, auditingTest, cookieData) {
    let ws = new WebSocket("ws://localhost:8100");

    // Listen for messages from the server.
    ws.onopen = function() {
        ws.send(JSON.stringify({
            id: "window",
            href: window.location.href,
            domain: window.location.hostname,
            path: window.location.pathname,
            protocol: window.location.protocol,
            addressAutoFill: addressAutoFillTest,
            bankingAutoFill: bankingAutoFillTest,
            safeBrowsing: safeBrowsingTest,
            browsingBlocking: browsingBlockingTest,
            tracking: trackingTest,
            auditing: auditingTest,
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