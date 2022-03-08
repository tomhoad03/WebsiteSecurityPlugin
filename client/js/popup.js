let resultsText = document.getElementById("results");

displayResults();

function displayResults() {
    // displays the results
    chrome.storage.sync.get("results", ({results}) => {
        resultsText.innerHTML = results;
    });
}
