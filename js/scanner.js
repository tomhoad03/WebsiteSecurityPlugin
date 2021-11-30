let scannerBtn = document.getElementById("scannerBtn");

scannerBtn.addEventListener("click", async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    function: vulnerabilityScanner,
  });
});

function vulnerabilityScanner() {
  console.log("Vulnerability Scanner");
}