const button = document.getElementById("analyzebtn");
const input = document.getElementById("urlInput");
const resultBox = document.getElementById("result");

button.addEventListener("click", () => {
  const url = input.value.trim();

  if (!url) {
    showResult("Please enter a URL", "error");
    return;
  }

  // Simple demo logic (replace later with real checks)
  const isPhishing = url.includes("@") || url.toLowerCase().includes("login") || url.toLowerCase().includes("verify");

  if (isPhishing) {
    showResult(`PHISHING URL\n${url}`, "phishing");
  } else {
    showResult("LEGITIMATE URL", "legit");
  }
});

function showResult(text, type) {
  resultBox.textContent = text;
  resultBox.className = `result ${type}`;
}
