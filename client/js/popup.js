let scoreText = document.getElementById("score");

// Display the score in the extension
chrome.storage.sync.get("score", ({score}) => {
    scoreText.innerHTML = score;
});