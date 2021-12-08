let reviewerBtn = document.getElementById("reviewerBtn");

// Runs when the popup loads
window.addEventListener('DOMContentLoaded', async() => {
    if (!window.location.href.startsWith("chrome")) {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        chrome.scripting.executeScript({
            target: { tabId: tab.id },
            function: basicReview,
        });
    }
    console.log("test");
});

// When clicked, the plugin performs code review.
reviewerBtn.addEventListener("click", async () => {
    if (!window.location.href.startsWith("chrome")) {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        chrome.scripting.executeScript({
            target: {tabId: tab.id},
            function: codeReview,
        });
    }
    console.log("test");
});

// Performs a basic code review of the website
function basicReview() {
    let href = window.location.href; // gets full href
    let domain = window.location.hostname; // host domain (local host for testbed)
    let path = window.location.pathname; // path and filename of the current page
    let protocol = window.location.protocol; // http or https

    if (protocol === "http:") {
        console.log("Website using HTTP protocols.")
    } else {
        console.log("Website using HTTPS protocols.")
    }
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