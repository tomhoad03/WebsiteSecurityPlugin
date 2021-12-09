let reviewerBtn = document.getElementById("reviewerBtn");

// Runs when the popup loads
window.addEventListener('DOMContentLoaded', async() => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: basicReview,
    });
});

// When clicked, the plugin performs code review.
reviewerBtn.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: {tabId: tab.id},
        function: codeReview,
    });
});

// Performs a basic code review of the websites
function basicReview() {
    let href = window.location.href; // gets full href
    let domain = window.location.hostname; // host domain (local host for testbed)
    let path = window.location.pathname; // path and filename of the current page
    let protocol = window.location.protocol; // http or https

    if (protocol === "HTTP:") {
        console.log("The website is using the HTTP protocol.");
    } else {
        console.log("The website is using the HTTP protocol.");
    }

    let ws = new WebSocket("ws://localhost:8080");

    ws.addEventListener("open", () => {
        console.log("We are connected.");
    })
}

// Performs a more advanced code review of the website
function codeReview() {
    let htmlElements = document.getElementsByTagName('html');
    for (let i = 0; i < htmlElements.length; i++) {
        console.log(htmlElements[i].innerHTML);
    }

    /*
    Validates HTML files for compliance against the W3C standards and performs linting to assess code quality against best practices.
    Find missing or unbalanced HTML tags in your documents, stray characters, duplicate IDs, missing or invalid attributes and other recommendations.
    Supports HTML5, SVG 1.1, MathML 3.0, ITS 2.0, RDFa Lite 1.1. Implementation is based on Validator.Nu.
     */
}