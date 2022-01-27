let resultsText = document.getElementById("results");

// Displays the results
chrome.storage.sync.get("results", ({results}) => {
    resultsText.innerHTML = results;
});