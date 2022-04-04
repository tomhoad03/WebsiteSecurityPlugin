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

chrome.runtime.onMessage.addListener(
    function(request) {
        try {
            if (request.msg === "results_sent") {
                let securityTest = request.data.content;

                // displays the results
                let percentage = ((securityTest.score / securityTest.maxScore) * 100).toFixed(2);

                // A+, A, A-, B+, B, B-, C+, C, C-, D with an interval of every 10%
                switch (true) {
                    case (percentage >= 90):
                        rating.innerHTML = "A+";
                        break;
                    case (percentage >= 80):
                        rating.innerHTML = "A";
                        break;
                    case (percentage >= 70):
                        rating.innerHTML = "A-";
                        break;
                    case (percentage >= 60):
                        rating.innerHTML = "B+";
                        break;
                    case (percentage >= 50):
                        rating.innerHTML = "B";
                        break;
                    case (percentage >= 40):
                        rating.innerHTML = "B-";
                        break;
                    case (percentage >= 30):
                        rating.innerHTML = "C+";
                        break;
                    case (percentage >= 20):
                        rating.innerHTML = "C";
                        break;
                    case (percentage >= 10):
                        rating.innerHTML = "C-";
                        break;
                    default:
                        rating.innerHTML = "D";
                        break;
                }

                const results = "<ul class=\"list-group\">" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Domain:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.domain + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Path:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.path + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Score:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + percentage + "%</span></li>" +
                    "<ul class=\"list-group\">" +
                    "</ul>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">HTTPS Protocols Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.httpsProtocolsTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Client Side Comments Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.clientSideCommentsTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Untrusted Links Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.untrustedLinksTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Address Auto Fill Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.addressAutoFillTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Banking Auto Fill Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.bankingAutoFillTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Safe Browsing Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.safeBrowsing1Test + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Safe Browsing Reporting Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.safeBrowsing2Test + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Tracking Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.trackingTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Link Auditing Enabled:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.auditingTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Cookie Security Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.cookieSecurityTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Timely Cookies Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.timelyCookiesTest + "</span></li>" +
                    "<ul class=\"list-group\">" +
                    "</ul>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Google Safe Browsing API:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.googleSafeBrowsingTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Unsafe Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityUnsafeTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API DNS Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityDnsValidTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Spamming Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualitySpammingTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Malware Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityMalwareTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Phishing Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityPhishingTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Suspicious Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualitySuspiciousTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Adult Content Test:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityAdultTest + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">IP Quality API Risk Score:" +
                    "<span class=\"badge bg-primary rounded-pill\">" + securityTest.ipQualityRiskScore + "</span></li>" +
                    "</ul>";

                const dashOffset = 472 - ((securityTest.score / securityTest.maxScore) * 472);

                const donut = "<linearGradient id=\"score-gradient\" x1=\"0\" y1=\"0\" x2=\"0.6\" y2=\"1\">" +
                    "<stop offset=\"0\" stop-color=\"#00FF00\"/>" +
                    "<stop offset=\"0.5\" stop-color=\"#FFFF00\"/>" +
                    "<stop offset=\"1\" stop-color=\"#FF0000\"/>" +
                    "</linearGradient>" +
                    "<circle cx=\"75\" cy=\"75\" r=\"68\" stroke-dashoffset=\"" + dashOffset + "\"></circle>\"";

                resultsText.innerHTML = results;
                donutScore.innerHTML = donut;
            }
        } catch (error) {
            console.log(error);
        }
    }
);