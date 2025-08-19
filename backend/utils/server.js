// server.js
const express = require("express");
const path = require("path");
const { detectPlatform } = require("./dnsHelpers");

const app = express();
const PORT = 3000;

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// API to detect platform
app.get("/api/detect-platform", async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  try {
    const result = await detectPlatform(domain);
    res.json({ platform: result.platform || "fallback" });
  } catch (err) {
    console.error("Detection error:", err);
    res.status(500).json({ platform: "fallback" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});