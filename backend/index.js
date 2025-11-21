// backend/index.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");
const morgan = require("morgan");
const helmet = require("helmet");
const { detectPlatform, scorePlatforms } = require("./utils/dnsHelpers");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
// Middleware
app.use(helmet());

app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy",
    "script-src 'self' https://code.jquery.com; img-src 'self' data: https://static.zohocdn.com");
  next();
});

app.use(cors({
  origin: process.env.CORS_ORIGIN || "https://sogqxt.tempavatar.click",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(morgan("combined"));
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));



// API route
app.get("/api/platform-detect", async (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: "No domain provided" });
  }

  try {
    const result = await detectPlatform(domain);
    const { topPlatforms } = scorePlatforms(
      result.mxHosts,
      result.spfTxts,
      result.dkimSelectors.map(d => d.record)
    );
    const platform = topPlatforms[0] || result.platform || "fallback";
    res.json({ platform });
  } catch (err) {
    console.error("Detection error:", err);
    res.status(500).json({ platform: "fallback" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Email platform detector running at http://localhost:${PORT}`);
});