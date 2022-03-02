let resultsText = document.getElementById("results");
let resultsUpdated = document.getElementById("isUpdated");
let currentHref1, resultsHref1;

if (resultsHref1 === currentHref1) {
    resultsUpdated.innerHTML = "Updated"
    console.log("Updated");
} else {
    resultsUpdated.innerHTML = "Updating"
    console.log("Updating");
}

// get current href
chrome.storage.sync.get("currentHref", (currentHref) => {
    currentHref1 = currentHref;
    console.log(currentHref);
});

// results href
chrome.storage.sync.get("resultsHref", (resultsHref) => {
    resultsHref1 = resultsHref;
    console.log(resultsHref);
});

// displays the results
chrome.storage.sync.get("results", ({results}) => {
    resultsText.innerHTML = results;
});