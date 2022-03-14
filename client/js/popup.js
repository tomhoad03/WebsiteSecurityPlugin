let resultsText = document.getElementById("results");
let donutScore= document.getElementById("donut");

displayResults();

function displayResults() {
    // displays the results
    chrome.storage.sync.get("results", ({results}) => {
        resultsText.innerHTML = results;
    });

    chrome.storage.sync.get("donut", ({donut}) => {
        donutScore.innerHTML = donut;
    });
}
