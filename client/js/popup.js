let resultsText = document.getElementById("results");

// displays the results
chrome.storage.sync.get("results", ({results}) => {
    resultsText.innerHTML = results;
});