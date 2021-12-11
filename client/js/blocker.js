let blockerBtn = document.getElementById("blockerBtn");

blockerBtn.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: adBlocker,
    });
});

function adBlocker() {
    console.log("Ad Blocker");
}