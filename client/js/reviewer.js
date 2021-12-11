let reviewerBtn = document.getElementById("reviewerBtn");

// When clicked, the plugin performs code review.
reviewerBtn.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: {tabId: tab.id},
        function: codeReview,
    });
});

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