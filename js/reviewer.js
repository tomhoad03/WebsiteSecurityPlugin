let reviewerBtn = document.getElementById("reviewerBtn");

chrome.storage.sync.get("color", ({color}) => {
    reviewerBtn.style.backgroundColor = color;
});

reviewerBtn.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: codeReview,
    });
});

function codeReview() {
    console.log("Code Review");
}