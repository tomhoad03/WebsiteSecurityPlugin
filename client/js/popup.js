let resultsText = document.getElementById("results");
let donutScore = document.getElementById("donut");
let rating = document.getElementById("rating");

chrome.runtime.sendMessage({
    msg: "results_request",
    data: {
        subject: "results",
        content: null
    }
});

console.log("results_request");

chrome.runtime.onMessage.addListener(
    function(request) {
        console.log("results_sent");

        if (request.msg === "results_sent") {
            let securityTest = request.data.content;

            console.log(securityTest);
            console.log(securityTest.domain);

            // displays the results
            let percentage = ((securityTest.score / securityTest.maxScore) * 100).toFixed(2);

            switch (true) {
                case (percentage >= 75):
                    rating.innerHTML = "A";
                    break;
                case (percentage >= 50):
                    rating.innerHTML = "B";
                    break;
                case (percentage >= 25):
                    rating.innerHTML = "C";
                    break;
                default:
                    rating.innerHTML = "D";
                    break;
            }

            const results = "<ul class=\"list-group\">" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Domain: " + securityTest.domain + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Path: " +  securityTest.path + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Score: " + percentage + "%</li>" +
                "<ul class=\"list-group\">" +
                "</ul>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">HTTPS Protocols Test: " + securityTest.httpsProtocolsTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Client Side Comments Test: " + securityTest.clientSideCommentsTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Untrusted Links Test: " + securityTest.untrustedLinksTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Basic XSS Test: " + securityTest.basicXXSTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Address Auto Fill Enabled: " + securityTest.addressAutoFillTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Banking Auto Fill Enabled: " + securityTest.bankingAutoFillTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Safe Browsing Enabled: " + securityTest.safeBrowsing1Test + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Safe Browsing Reporting Enabled: " + securityTest.safeBrowsing2Test + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Tracking Enabled: " + securityTest.trackingTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Link Auditing Enabled: " + securityTest.auditingTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Cookie Security Test: " + securityTest.cookieSecurityTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Timely Cookies Test: " + securityTest.timelyCookiesTest + "</li>" +
                "<ul class=\"list-group\">" +
                "</ul>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">Google Safe Browsing API: " + securityTest.googleSafeBrowsingTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Unsafe Test: " + securityTest.ipQualityUnsafeTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API DNS Test: " + securityTest.ipQualityDnsValidTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Spamming Test: " + securityTest.ipQualitySpammingTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Malware Test: " + securityTest.ipQualityMalwareTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Phishing Test: " + securityTest.ipQualityPhishingTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Suspicious Test: " + securityTest.ipQualitySuspiciousTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Adult Content Test: " + securityTest.ipQualityAdultTest + "</li>" +
                "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Risk Score: " + securityTest.ipQualityRiskScore + "</li>" +
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