let detectorBtn = document.getElementById("detectorBtn");

chrome.storage.sync.get("color", ({color}) => {
    detectorBtn.style.backgroundColor = color;
});

detectorBtn.addEventListener("click", async () => {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: malwareDetector,
    });
});

function malwareDetector() {
    console.log("Malware Detector");
}