const express = require('express');
const path = require('path');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Middleware to read JSON data and serve your CSS/JS files
app.use(express.json());
app.use('/static', express.static(path.join(__dirname, 'static')));

// Route to serve your HTML page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'index.html'));
});

// The "Secure Bridge" - This is where we will eventually add API calls
app.post('/analyze', async (req, res) => {
    try {
        const { url } = req.body;
        const API_KEY = process.env.VT_API_KEY;

        if (!url) return res.status(400).json({ error: "No URL provided" });
        if (!API_KEY) return res.json({ status: "No API Key", message: "Check your .env file" });

        // Base64 encode the URL correctly for VT V3 API
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, "");

        const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': API_KEY }
        });

        res.json({
            status: "Success",
            vt_results: response.data.data.attributes.last_analysis_stats
        });

    } catch (error) {
        // This is the most important part: handling the "Resource Not Found"
        if (error.response && error.response.status === 404) {
            return res.json({
                status: "New URL",
                message: "This URL hasn't been scanned by VT yet. Using local heuristics."
            });
        }

        console.error("VT API Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ status: "Error", message: "Internal Server Error" });
    }
});

app.listen(PORT, () => {
    console.log(`SOC Analysis Tool running at http://localhost:${PORT}`);
});