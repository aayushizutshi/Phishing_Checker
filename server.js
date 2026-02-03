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
app.post('/analyze', async(req, res) => {
    const { url } = req.body;
    const API_KEY = process.env.VT_API_KEY;
    if (!API_KEY) {
        // Fallback if no API key is set yet
        return res.json({ 
            status: "Local Heuristics Only", 
            message: "Server is running, but API key is missing." 
        });
    }
    
    try {
        // VirusTotal V3 encoding logic
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, "");
        
        const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: { 'x-apikey': API_KEY }
        });

        res.json({
            status: "Success",
            vt_results: response.data.data.attributes.last_analysis_stats
        });
    } catch (error) {
        res.status(500).json({ error: "API lookup failed" });
    }
});

app.listen(PORT, () => {
    console.log(`SOC Analysis Tool running at http://localhost:${PORT}`);
});