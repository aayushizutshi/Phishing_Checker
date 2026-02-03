#  Full-Stack Phishing Analysis Tool

A professional-grade Security Operations Center (SOC) triage tool designed to identify malicious URLs using a combination of **local heuristic analysis** and **global threat intelligence** via the VirusTotal API.

##  Overview
When a SOC analyst receives a suspicious link, they need a safe way to investigate it without accidentally infecting their own machine. This tool solves that by:
1.  **Analyzing** the URL for common "red flags" locally.
2.  **Cross-referencing** the URL with 70+ security vendors in real-time.
3.  **Defanging** the link to make it safe for documentation and sharing.

##  Key Features
* **Secure API Bridge:** Built with a Node.js/Express backend to keep API keys hidden from the client-side, preventing credential theft.
* **Layered Detection:** Uses local Regex patterns to catch "Zero-Day" phishing signs (e.g., credential obfuscation, IP-based hosting) even if they haven't been reported to VirusTotal yet.
* **Safety First (Defanging):** Automatically converts dangerous links (e.g., `http://`) into safe strings (e.g., `hXXp://`) to ensure the report is non-clickable.
* **Intelligence Summary:** Provides a clear breakdown of "Malicious," "Suspicious," and "Harmless" ratings from global security engines.

##  Tech Stack
* **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
* **Backend:** Node.js, Express.js
* **API:** VirusTotal V3 API (Axios for HTTP requests)
* **Environment:** Dotenv for secure secret management

##  Security Best Practices Implemented
* **Secret Management:** Utilized a `.env` file to store sensitive API credentials. Configured `.gitignore` to ensure these secrets are never pushed to public version control.
* **Backend Proxying:** Implemented a backend route to handle API calls, ensuring the API key never touches the user's browser (protecting against "Inspect Element" key theft).
* **Input Sanitization:** Trimmed and validated user input to prevent malformed requests to the backend.


##  Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/phishing-checker.git](https://github.com/your-username/phishing-checker.git)
   cd phishing-checker
1. run `npm install`.
2. Register for a free API key at VirusTotal.
3. Create a `.env` file and add your key: `VT_API_KEY=your_key_here`.
4. Launch the secure server: `node server.js`.