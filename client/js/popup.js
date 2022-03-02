let resultsText = document.getElementById("results");

refresh();

// displays the results
function refresh() {
    chrome.storage.sync.get("results", ({results}) => {
        resultsText.innerHTML = results;
    });
}