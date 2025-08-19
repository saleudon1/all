const dns = require("dns").promises;
const net = require("net");

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

const knownPlatforms = {
  google: ["google.com", "gmail.com", "aspmx.l.google.com", "_spf.google.com"],
  zoho: ["zoho.com", "mx.zoho.com", "_spf.zoho.com"],
  yahoo: ["yahoodns.net", "yahoo.com"],
  att: ["att.net", "yahoodns.net", "_spf.att.net"],
  outlook: ["outlook.com", "office365.com", "protection.outlook.com", "_spf.protection.outlook.com"],
  zimbra: ["zimbra", "zimbra.mail"],
  cpanel: ["cpanel", "webmail", "secureserver.net"],
  eim: ["eim.ae", "mail.eim.ae", "_spf.eim.ae"],
  protonmail: ["protonmail.ch", "proton.me", "mail.protonmail.ch", "_spf.protonmail.ch"],
  fastmail: ["fastmail.com", "messagingengine.com", "_spf.messagingengine.com"],
  yandex: ["yandex.ru", "yandex.net", "mx.yandex.net", "_spf.yandex.net"],
  gmx: ["gmx.net", "mx00.gmx.net", "_spf.gmx.net"],
  rackspace: ["rackspace.com", "emailsrvr.com", "_spf.emailsrvr.com"],
  icloud: ["icloud.com", "me.com", "mac.com", "_spf.apple.com"]
};

// 🔌 Port probing for cPanel
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

async function detectPlatform(domain) {
  const cachedResult = getCache(domain);
  if (cachedResult) return cachedResult;

  const result = {
    platform: "unknown",
    mxHosts: [],
    spfTxts: [],
    dkimSelectors: [],
    error: null
  };

  try {
    const mxRecords = await dns.resolveMx(domain);
    result.mxHosts = mxRecords.map(r => r.exchange.toLowerCase());

    const txtRecords = await dns.resolveTxt(domain);
    result.spfTxts = txtRecords.flat().filter(txt => txt.includes("v=spf1"));

    const commonSelectors = ["default", "selector1", "selector2"];
    for (const selector of commonSelectors) {
      try {
        const dkimTxt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
        result.dkimSelectors.push({
          selector,
          record: dkimTxt.flat().join("")
        });
      } catch {
        // Ignore missing DKIM
      }
    }

    const allValues = [
      ...result.mxHosts,
      ...result.spfTxts,
      ...result.dkimSelectors.map(d => d.record)
    ].join(" ").toLowerCase();

    for (const [platform, keywords] of Object.entries(knownPlatforms)) {
      if (keywords.some(keyword => allValues.includes(keyword))) {
        result.platform = platform;
        break;
      }
    }

    // 🧪 Check for active cPanel ports
    const isCpanel = await probePort(domain, 2095) || await probePort(domain, 2096);
    if (isCpanel) {
      result.platform = "cpanel";
    }

    setCache(domain, result);
  } catch (err) {
    result.error = "DNS resolution failed";
    console.error("DNS error for domain:", domain, err);
  }

  return result;
}

const scoringWeights = {
  mx: 3,
  spf: 2,
  dkim: 1
};

function scorePlatforms(mxHosts, spfRecords, dkimRecords) {
  const scores = {};

  for (const [platform, indicators] of Object.entries(knownPlatforms)) {
    scores[platform] = 0;
    const allIndicators = indicators.map(s => s.toLowerCase());

    mxHosts.forEach(mx => {
      if (allIndicators.some(i => mx.includes(i))) {
        scores[platform] += scoringWeights.mx;
      }
    });

    spfRecords.forEach(spf => {
      if (allIndicators.some(i => spf.includes(i))) {
        scores[platform] += scoringWeights.spf;
      }
    });

    dkimRecords.forEach(dkim => {
      if (allIndicators.some(i => dkim.includes(i))) {
        scores[platform] += scoringWeights.dkim;
      }
    });
  }

  const highestScore = Math.max(...Object.values(scores));
  const topPlatforms = Object.entries(scores)
    .filter(([_, score]) => score === highestScore)
    .map(([platform]) => platform);

  return {
    topPlatforms,
    scores
  };
}

module.exports = { detectPlatform, scorePlatforms };