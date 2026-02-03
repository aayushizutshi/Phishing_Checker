#  SOC Phishing Investigation & Triage Tool

A specialized security application designed to streamline the investigation of suspicious URLs using heuristic analysis and industry-standard threat intelligence.

##  Technical Highlights
* **Secure Architecture**: Implemented a Node.js/Express backend to securely proxy API requests and protect private credentials.
* **Dynamic Risk Scoring**: Evaluates URLs based on malicious indicators such as IP-based hosting, urgency keywords, and subdomain obfuscation.
* **Safe Handling**: Features automatic URL defanging (e.g., `hXXp://`) to prevent accidental execution of malicious links during analysis.

##  Setup Instructions
1. Clone the repository and run `npm install`.
2. Register for a free API key at VirusTotal.
3. Create a `.env` file and add your key: `VT_API_KEY=your_key_here`.
4. Launch the secure server: `node server.js`.