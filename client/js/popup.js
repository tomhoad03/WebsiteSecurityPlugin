let resultsText = document.getElementById("results");
let donutScore= document.getElementById("donut");

chrome.runtime.sendMessage({
    msg: "results_request",
    data: {
        subject: "results",
        content: null
    }
});

console.log("results_request");

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
        console.log("results_sent");

        if (request.msg === "results_sent") {
            let securityTest = request.data.content;

            console.log(securityTest);
            console.log(securityTest.domain);

            // displays the results
            const results = "<ul>" +
                "<li>Domain: " + securityTest.domain + "</li>" +
                "<li>Score: " + ((securityTest.score / securityTest.maxScore) * 100).toFixed(2) + "%</li>" +
                "<li>HTTPS Protocols: " + securityTest.httpsProtocolsTest + "</li>" +
                "<li>Client Side Comments: " + securityTest.clientSideCommentsTest + "</li>" +
                "<li>Untrusted Links: " + securityTest.untrustedLinksTest + "</li>" +
                "<li>Basic XSS Test: " + securityTest.basicXXSTest + "</li>" +
                "<li>Address Auto Fill: " + securityTest.addressAutoFill + "</li>" +
                "<li>Banking Auto Fill: " + securityTest.bankingAutoFill + "</li>" +
                "<li>Cookies Security: " + securityTest.cookieSecurity + "</li>" +
                "<li>Timely Cookies: " + securityTest.timelyCookies + "</li>" +
                "<li>Safe Browsing API: " + securityTest.safeBrowsing + "</li>" +
                "</ul>"

            const dashOffset = 472 - ((securityTest.score / securityTest.maxScore) * 472)

            const donut = "<linearGradient id=\"score-gradient\" x1=\"0\" y1=\"0\" x2=\"0.6\" y2=\"1\">" +
                "<stop offset=\"0\" stop-color=\"#00FF00\"/>" +
                "<stop offset=\"0.5\" stop-color=\"#FFFF00\"/>" +
                "<stop offset=\"1\" stop-color=\"#FF0000\"/>" +
                "</linearGradient>" +
                "<circle cx=\"75\" cy=\"75\" r=\"68\" stroke-dashoffset=\"" + dashOffset + "\"></circle>\""

            resultsText.innerHTML = results;
            donutScore.innerHTML = donut;
        }
    }
);
