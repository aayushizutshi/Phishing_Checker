const button = document.getElementById("analyzebtn");
const input = document.getElementById("urlInput");
const resultBox = document.getElementById("result");

button.addEventListener("click", async () => {
  const url = input.value.trim();

  if (!url) {
    showResult("Please enter a URL", "error");
    return;
  }

  let vtReport = "No VirusTotal data available.";
  let vtStatus = "Local Only";

  // --- TALK TO SECURE BACKEND ---
  try {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    const serverData = await response.json();

    // FIX: Check serverData.status instead of just serverData
    if (serverData.status === "Success") {
      const stats = serverData.vt_results;
      vtStatus = "API Success";
      vtReport = `[VirusTotal Intelligence]\nMalicious: ${stats.malicious} | Suspicious: ${stats.suspicious} | Harmless: ${stats.harmless}`;
    } else {
      vtReport = `[VT Warning]: ${serverData.message}`;
    }
  } catch (err) {
    vtReport = "[Error]: Backend Unreachable.";
  }

  // --- LOCAL HEURISTIC LOGIC ---
  let riskScore = 0;
  let artifacts = [];

  const ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipRegex.test(url)) {
    riskScore += 40;
    artifacts.push("Suspicious IP-based URL");
  }
  if (url.includes("@")) {
    riskScore += 50;
    artifacts.push("Credential Obfuscation (@ symbol)");
  }
  const sensitiveKeywords = ["login", "verify", "update", "banking", "secure"];
  sensitiveKeywords.forEach(word => {
    if (url.toLowerCase().includes(word)) {
      riskScore += 20;
      artifacts.push(`Urgency Keyword Detected: ${word}`);
    }
  });
  const dotCount = (url.match(/\./g) || []).length;
  if (dotCount > 3) {
    riskScore += 20;
    artifacts.push("Excessive Subdomains detected");
  }

  // --- DEFANGING & FINAL REPORT ---
  const defanged = url.replace(/http/g, "hXXp").replace(/\./g, "[.]");

  const header = riskScore >= 40 ? "⚠️ MALICIOUS ACTIVITY DETECTED" : "✅ URL APPEARS CLEAN";
  const finalType = riskScore >= 40 ? "phishing" : "legit";

  const fullReport = `${header}\n---------------\nRisk Score: ${riskScore}\nDefanged: ${defanged}\n\n${vtReport}\n\nArtifacts:\n${artifacts.length > 0 ? artifacts.join("\n") : "No local IOCs found."}`;

  showResult(fullReport, finalType);
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
