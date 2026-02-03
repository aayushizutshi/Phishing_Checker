const button = document.getElementById("analyzebtn");
const input = document.getElementById("urlInput");
const resultBox = document.getElementById("result");

button.addEventListener("click", async () => {
  const url = input.value.trim();

  if (!url) {
    showResult("Please enter a URL", "error");
    return;
  }

  //Talk to secure backend
  try {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    const serverData = await response.json();
    console.log("Backend Triage Status:", serverData.status);
  } catch (err) {
    console.error("Backend unreachable");
  }

  
  let riskScore = 0;
  let artifacts = [];

  //IP based hosting
  const ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipRegex.test(url)) {
    riskScore += 40;
    artifacts.push("Suspicious Ip-based URL")
  }
  //Check for @ in URL
  if (url.includes("@")) {
    riskScore += 50;
    artifacts.push("Credential Obfscation (@ symbol)");
  }
  //Check for sensitive keywords in subdomain
  const sensitiveKeywords = ["login", "verify", "update", "banking", "secure"];
  sensitiveKeywords.forEach(word => {
    if (url.toLowerCase().includes(word)) {
      riskScore += 20;
      artifacts.push(`Urgency Keyword Detected: ${word}`);
    }
  });
  //Check for excessive subdomains
  const dotCount = (url.match(/\./g) || []).length;
  if (dotCount > 3) {
    riskScore += 20;
    artifacts.push("Excessive Subdomains detected");
  }

  // --- DEFANGING FOR SAFETY ---
  const defanged = url.replace(/http/g, "hXXp").replace(/\./g, "[.]");

  // --- VERDICT LOGIC ---
  if (riskScore >= 40) {
    const report = `MALICIOUS ACTIVITY DETECTED\nRisk Score: ${riskScore}\nDefanged: ${defanged}\n\nArtifacts:\n${artifacts.join("\n")}`;
    showResult(report, "phishing");
  }
  else {
    showResult(`URL APPEARS CLEAN\nDefanged: ${defanged}\nNo immediate IOCs found.`, "legit");
  }

});

function showResult(text, type) {
  resultBox.innerHTML = `<pre style="text-align: left; font-size: 12px;">${text}</pre>`;
  // resultBox.textContent = text;
  resultBox.className = `result ${type}`;
  resultBox.classList.remove("hidden");

  // Show the copy button only if it's not an error
  if (type !== "error") {
    copyBtn.classList.remove("hidden");
  } else {
    copyBtn.classList.add("hidden");
  }

  // Handle the copy functionality
  copyBtn.onclick = () => {
    navigator.clipboard.writeText(resultBox.innerText);
    alert("Investigation Report copied to clipboard!");
  };
}
