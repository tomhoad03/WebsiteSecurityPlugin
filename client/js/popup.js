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
                    case (percentage >= 95):
                        rating.innerHTML = "A+";
                        break;
                    case (percentage >= 90):
                        rating.innerHTML = "A";
                        break;
                    case (percentage >= 85):
                        rating.innerHTML = "A-";
                        break;
                    case (percentage >= 80):
                        rating.innerHTML = "B+";
                        break;
                    case (percentage >= 75):
                        rating.innerHTML = "B";
                        break;
                    case (percentage >= 70):
                        rating.innerHTML = "B-";
                        break;
                    case (percentage >= 65):
                        rating.innerHTML = "C+";
                        break;
                    case (percentage >= 60):
                        rating.innerHTML = "C";
                        break;
                    case (percentage >= 55):
                        rating.innerHTML = "C-";
                        break;
                    default:
                        rating.innerHTML = "D";
                        break;
                }

                const results = "<ul class=\"list-group\">" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Domain:" +
                    "<span class=\"badge rounded-pill\" id=\"general\">" + securityTest.domain + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Path:" +
                    "<span class=\"badge rounded-pill\" id=\"general\">" + securityTest.path + "</span></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\">Score:" +
                    "<span class=\"badge rounded-pill\" id=\"general\">" + percentage + "%</span></li>" +
                    "<ul class=\"list-group\">" +
                    "</ul>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div> Cross Origin Scripts Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.crossOriginScriptsTest + ">" + passedText(securityTest.crossOriginScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test for scripts using the correct CORS policy.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Integrity Scripts Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.integrityScriptsTest + ">" + passedText(securityTest.integrityScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test for scripts using a checksum.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Nonce Scripts Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.nonceScriptsTest + ">" + passedText(securityTest.nonceScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test for scripts using a cryptographic nonce.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>External Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.externalScriptsTest + ">" + passedText(securityTest.externalScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for scripts used from an external source.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Dynamic Execution Scripts Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.dynamicExecutionScriptsTest + ">" + passedText(securityTest.dynamicExecutionScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for potential code patterns used for malicious code execution.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Outdated Scripts Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.outdatedScriptsTest + ">" + passedText(securityTest.outdatedScriptsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for outdated script references.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Trusted Links Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.trustedLinksTest + ">" + passedText(securityTest.trustedLinksTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for untrustworthy links.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>HTTPS Protocols Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.httpsProtocolsTest + ">" + passedText(securityTest.httpsProtocolsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for the usage of HTTPS protocols.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Client Side Comments Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.clientSideCommentsTest + ">" + passedText(securityTest.clientSideCommentsTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check for comments left in code that may reveal sensitive information.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Address Auto Fill Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.addressAutoFillTest + ">" + passedText(securityTest.addressAutoFillTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser will autofill your address.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Banking Auto Fill Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.bankingAutoFillTest + ">" + passedText(securityTest.bankingAutoFillTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser will autofill your banking details.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Safe Browsing Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.safeBrowsingTest + ">" + passedText(securityTest.safeBrowsingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser is using safe browsing features.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Safe Browsing Reporting Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.browsingBlockingTest + ">" + passedText(securityTest.browsingBlockingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser is blocking unsafe content.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Tracking Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.trackingTest + ">" + passedText(securityTest.trackingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser has allowed tracking software.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Link Auditing Enabled:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.auditingTest + ">" + passedText(securityTest.auditingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if your browser is checking for unsafe links.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Cookie Security Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.cookieSecurityTest + ">" + passedText(securityTest.cookieSecurityTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if all cookies associated with the current website are secure.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Timely Cookies Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.timelyCookiesTest + ">" + passedText(securityTest.timelyCookiesTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if all cookies associated with the current website are not outdated.</i></small></div></li>" +
                    "<ul class=\"list-group\">" +
                    "</ul>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>Google Safe Browsing API:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.googleSafeBrowsingTest + ">" + passedText(securityTest.googleSafeBrowsingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website is registered safe by Google.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Unsafe Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualityUnsafeTest + ">" + passedText(securityTest.ipQualityUnsafeTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website is registered safe by IPQualityScore.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API DNS Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualityDnsValidTest + ">" + passedText(securityTest.ipQualityDnsValidTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the website DNS is valid.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Spamming Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualitySpammingTest + ">" + passedText(securityTest.ipQualitySpammingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website has had a recent spamming attack.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Malware Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualityMalwareTest + ">" + passedText(securityTest.ipQualityMalwareTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website has had a recent malware attack.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Phishing Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualityPhishingTest + ">" + passedText(securityTest.ipQualityPhishingTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website has had a recent phishing attack.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Suspicious Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualitySuspiciousTest + ">" + passedText(securityTest.ipQualitySuspiciousTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website has had a recent malicious attack.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Adult Content Test:" +
                    "<span class=\"badge rounded-pill\" id=" + securityTest.ipQualityAdultTest + ">" + passedText(securityTest.ipQualityAdultTest) + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check if the current website hosts adult content.</i></small></div></li>" +
                    "<li class=\"list-group-item justify-content-between align-items-center\"><div>IP Quality API Risk Score:" +
                    "<span class=\"badge rounded-pill\" id=\"general\">" + securityTest.ipQualityRiskScore + "</span></div>" +
                    "<div><small class=\"mb-1\"><i>Test to check the score given by IPQualityScore for the website. Lower is better.</i></small></div></li>" +
                    "</ul>";

                const dashOffset = (472 - ((securityTest.score / securityTest.maxScore) * 472)) * 2;

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

function passedText(value) {
    if (value) {
        return "Passed";
    } else {
        return "Not Passed";
    }
}