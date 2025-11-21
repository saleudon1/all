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

const DEFAULT_CORS_ORIGINS = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://saleudon1.github.io",
  "https://future.tskg.dpdns.org",
  "https://ftu.fly.dev",
];

const envOrigins = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const allowedOrigins = Array.from(new Set([...DEFAULT_CORS_ORIGINS, ...envOrigins]));

// Middleware
// Middleware
app.use(helmet());

app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy",
    "script-src 'self' https://code.jquery.com; img-src 'self' data: https://static.zohocdn.com");
  next();
});

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error(`Origin ${origin} not allowed by CORS policy`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(morgan("combined"));
app.use(express.json());
// Serve the static site that will also be published via GitHub Pages
app.use(express.static(path.join(__dirname, "../docs")));



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
