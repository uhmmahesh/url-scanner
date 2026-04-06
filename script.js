const form = document.getElementById("url-form");
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const statusLabel = document.getElementById("status-label");
const statusPercent = document.getElementById("status-percent");
const statusBarFill = document.getElementById("status-bar-fill");

const urlInfoBody = document.getElementById("url-info-body");
const threatIndicatorsBody = document.getElementById("threat-indicators-body");
const spoofDetectionBody = document.getElementById("spoof-detection-body");
const riskScoreBody = document.getElementById("risk-score-body");
const riskScoreValue = document.getElementById("risk-score-value");
const riskScoreLabel = document.getElementById("risk-score-label");
const riskMeterFill = document.getElementById("risk-meter-fill");
const riskFactorsList = document.getElementById("risk-factors");
const summaryBody = document.getElementById("summary-body");

const cards = [
  document.getElementById("card-url-info"),
  document.getElementById("card-threat-indicators"),
  document.getElementById("card-spoof-detection"),
  document.getElementById("card-risk-score"),
  document.getElementById("card-summary"),
];

const SUSPICIOUS_TLDS = [
  "zip",
  "mov",
  "click",
  "work",
  "cam",
  "party",
  "asia",
  "country",
  "gq",
  "ml",
  "tk",
  "cf",
  "top",
  "loan",
  "info",
  "download",
  "science",
  "xyz",
];

const SHORTENER_HOSTS = [
  "bit.ly",
  "tinyurl.com",
  "goo.gl",
  "t.co",
  "ow.ly",
  "buff.ly",
  "is.gd",
  "cutt.ly",
];

const BRAND_KEYWORDS = [
  "google",
  "facebook",
  "instagram",
  "whatsapp",
  "microsoft",
  "apple",
  "icloud",
  "paypal",
  "bank",
  "amazon",
  "netflix",
  "spotify",
  "github",
  "telegram",
];

const PHISHING_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "update",
  "payment",
  "invoice",
  "account",
  "password",
  "reset",
  "unlock",
  "confirm",
  "free",
  "win",
  "prize",
  "bonus",
];

async function resolveIpAddress(hostname) {
  try {
    if (isIpAddress(hostname)) return hostname;
    const response = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
    const data = await response.json();
    if (data && data.Answer && data.Answer.length > 0) {
      const aRecord = data.Answer.find(r => r.type === 1);
      if (aRecord) return aRecord.data;
    }
  } catch (error) {
    console.error("DNS resolution error:", error);
  }
  return null;
}

function safeParseUrl(input) {
  try {
    if (!/^https?:\/\//i.test(input)) {
      return new URL("https://" + input);
    }
    return new URL(input);
  } catch {
    return null;
  }
}

function isIpAddress(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function getTld(hostname) {
  const parts = hostname.split(".");
  if (parts.length < 2) return "";
  return parts[parts.length - 1].toLowerCase();
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

async function analyzeUrl(url) {
  const original = url.trim();
  const parsed = safeParseUrl(original);
  if (!parsed) {
    return { error: "Unable to parse URL. Please check the format." };
  }

  const { protocol, hostname, pathname, search } = parsed;
  const hostLower = hostname.toLowerCase();
  const full = parsed.href;

  const info = {
    protocol,
    hostname,
    pathname: pathname || "/",
    query: search || "",
    length: full.length,
    tld: getTld(hostname),
    isIp: isIpAddress(hostname),
    subdomainCount: Math.max(hostname.split(".").length - 2, 0),
    resolvedIp: await resolveIpAddress(hostname),
  };

  const indicators = [];
  let score = 0;
  const scoreFactors = [];

  const https = protocol === "https:";
  indicators.push({
    level: https ? "safe" : "warn",
    label: https ? "HTTPS enabled" : "No HTTPS detected",
    detail: https
      ? "Traffic between browser and server is encrypted, but this does not guarantee safety."
      : "Lack of HTTPS is unusual for modern legitimate sites.",
  });
  if (!https) {
    score += 15;
    scoreFactors.push("Connection is not using HTTPS.");
  }

  if (info.isIp) {
    indicators.push({
      level: "danger",
      label: "IP address in place of domain",
      detail:
        "Legitimate services rarely use raw IP addresses. This is a common tactic in malicious links.",
    });
    score += 25;
    scoreFactors.push("URL uses a raw IP address instead of a domain.");
  }

  const tldSuspicious = SUSPICIOUS_TLDS.includes(info.tld);
  if (tldSuspicious) {
    indicators.push({
      level: "warn",
      label: `Suspicious TLD: .${info.tld}`,
      detail:
        "This top‑level domain has historically been associated with abuse or bulk registrations.",
    });
    score += 12;
    scoreFactors.push(`Top‑level domain .${info.tld} is often abused.`);
  } else if (info.tld) {
    indicators.push({
      level: "safe",
      label: `TLD: .${info.tld}`,
      detail: "No obvious red flags for this top‑level domain.",
    });
  }

  const isShortener = SHORTENER_HOSTS.includes(hostLower);
  if (isShortener) {
    indicators.push({
      level: "warn",
      label: "URL shortening service",
      detail:
        "Shortened URLs hide the real destination and are frequently used in phishing campaigns.",
    });
    score += 15;
    scoreFactors.push("URL uses a shortening service that hides destination.");
  }

  if (info.subdomainCount >= 3) {
    indicators.push({
      level: "warn",
      label: "Many nested subdomains",
      detail:
        "Large subdomain chains are sometimes used to mimic trusted infrastructure.",
    });
    score += 10;
    scoreFactors.push("Hostname contains an unusually high number of subdomains.");
  }

  const includesAt = full.includes("@");
  if (includesAt) {
    indicators.push({
      level: "danger",
      label: "Contains @ symbol",
      detail:
        "Attackers sometimes use @ to hide the actual destination host to the right of the symbol.",
    });
    score += 18;
    scoreFactors.push("URL uses @ symbol, which can conceal the true destination host.");
  }

  const hasLongPath = info.length > 120 || pathname.length > 60 || search.length > 80;
  if (hasLongPath) {
    indicators.push({
      level: "warn",
      label: "Unusually long URL",
      detail:
        "Very long URLs can be used to stuff tracking parameters or obfuscate payloads.",
    });
    score += 10;
    scoreFactors.push("URL is unusually long and potentially obfuscated.");
  }

  const keywordHits = [];
  const lowerFull = full.toLowerCase();
  PHISHING_KEYWORDS.forEach((kw) => {
    if (lowerFull.includes(kw)) {
      keywordHits.push(kw);
    }
  });
  if (keywordHits.length) {
    indicators.push({
      level: "danger",
      label: "Phishing‑like keywords present",
      detail: `URL contains the following sensitive terms: ${keywordHits.join(
        ", "
      )}. This is common in credential‑harvesting links.`,
    });
    score += 20;
    scoreFactors.push("Contains sensitive or phishing‑style keywords.");
  }

  const punycode = hostLower.includes("xn--");
  if (punycode) {
    indicators.push({
      level: "warn",
      label: "Punycode in hostname",
      detail:
        "Internationalized domains encoded as punycode can be used to visually imitate trusted brands.",
    });
    score += 10;
    scoreFactors.push("Hostname uses punycode, which may enable look‑alike attacks.");
  }

  const spoofFindings = [];
  const registeredDomain =
    info.subdomainCount > 0
      ? hostname
        .split(".")
        .slice(-2)
        .join(".")
      : hostname;

  BRAND_KEYWORDS.forEach((brand) => {
    const brandLower = brand.toLowerCase();
    if (registeredDomain.includes(brandLower)) {
      const domainRoot = registeredDomain.split(".")[0];
      const distance = levenshtein(domainRoot, brandLower);
      if (domainRoot !== brandLower && distance <= 2) {
        spoofFindings.push({
          level: "danger",
          label: `Look‑alike domain: ${registeredDomain}`,
          detail: `The domain resembles "${brand}" and may be attempting to spoof it (edit distance ${distance}).`,
        });
        score += 25;
        scoreFactors.push(
          `Domain looks visually similar to the brand "${brand}".`
        );
      } else if (registeredDomain !== `${brandLower}.com`) {
        spoofFindings.push({
          level: "warn",
          label: `Brand keyword embedded: ${brand}`,
          detail: `Contains popular brand name "${brand}" but is not the primary official domain.`,
        });
        score += 12;
        scoreFactors.push(
          `Domain embeds the brand name "${brand}" without being the official host.`
        );
      }
    }
  });

  if (!spoofFindings.length) {
    spoofFindings.push({
      level: "safe",
      label: "No obvious brand spoofing detected",
      detail:
        "Domain does not closely resemble a small set of common consumer brands used in phishing.",
    });
  }

  let normalized = Math.max(0, Math.min(100, score));
  let qualitative;
  if (normalized <= 25) {
    qualitative = "Low risk (heuristically benign)";
  } else if (normalized <= 60) {
    qualitative = "Medium risk (requires caution)";
  } else {
    qualitative = "High risk (likely unsafe)";
  }

  if (normalized === 0) {
    scoreFactors.push(
      "No obvious heuristics triggered. Still verify sender and context before interacting."
    );
  }

  return {
    original,
    parsed,
    info,
    indicators,
    spoofFindings,
    score: normalized,
    qualitative,
    scoreFactors,
  };
}

function setStatus(label, percent) {
  statusLabel.textContent = label;
  statusPercent.textContent = `${percent}%`;
  statusBarFill.style.width = `${percent}%`;
}

function resetCards() {
  cards.forEach((card) => card.classList.remove("scanned"));
}

function flagCardScanned(cardId, delay = 0) {
  const card = document.getElementById(cardId);
  if (!card) return;
  setTimeout(() => {
    card.classList.remove("scanned");
    void card.offsetWidth;
    card.classList.add("scanned");
  }, delay);
}

function renderUrlInfo(result) {
  const { info, parsed } = result;
  urlInfoBody.innerHTML = `
    <div class="meta-grid">
      <div>
        <div class="meta-label">Protocol</div>
        <div class="meta-value">${info.protocol.replace(":", "").toUpperCase()}</div>
      </div>
      <div>
        <div class="meta-label">Length</div>
        <div class="meta-value">${info.length} chars</div>
      </div>
      <div>
        <div class="meta-label">Hostname</div>
        <div class="meta-value">${info.hostname}</div>
      </div>
      <div>
        <div class="meta-label">Top‑Level Domain</div>
        <div class="meta-value">.${info.tld || "n/a"}</div>
      </div>
      <div>
        <div class="meta-label">Path</div>
        <div class="meta-value">${info.pathname || "/"}</div>
      </div>
      <div>
        <div class="meta-label">Resolved IP</div>
        <div class="meta-value">${info.resolvedIp || "Unresolved"}</div>
      </div>
      <div>
        <div class="meta-label">Query String</div>
        <div class="meta-value">${info.query || "—"}</div>
      </div>
    </div>
    <div class="chip-row">
      <span class="chip ${info.isIp ? "negative" : "positive"}">${info.isIp ? "IP address host" : "Named host"
    }</span>
      <span class="chip ${info.subdomainCount >= 1
      ? info.subdomainCount >= 3
        ? "warning"
        : "positive"
      : "positive"
    }">${info.subdomainCount} subdomain${info.subdomainCount === 1 ? "" : "s"
    }</span>
      <span class="chip">${parsed.port ? `Port ${parsed.port}` : "Default port"
    }</span>
    </div>
  `;

  flagCardScanned("card-url-info");
}

function renderIndicators(result) {
  const { indicators } = result;
  const iconFor = (level) => {
    if (level === "safe") return "✓";
    if (level === "warn") return "!";
    return "⚠";
  };
  const classFor = (level) => {
    if (level === "safe") return "safe";
    if (level === "warn") return "warn";
    return "danger";
  };

  threatIndicatorsBody.innerHTML = `
    <ul class="indicator-list">
      ${indicators
      .map(
        (i) => `
        <li>
          <span class="indicator-icon ${classFor(i.level)}">${iconFor(
          i.level
        )}</span>
          <div>
            <span class="indicator-label">${i.label}</span>
            <span class="indicator-extra">${i.detail}</span>
          </div>
        </li>
      `
      )
      .join("")}
    </ul>
  `;

  flagCardScanned("card-threat-indicators", 80);
}

function renderSpoof(result) {
  const { spoofFindings } = result;
  const iconFor = (level) => {
    if (level === "safe") return "◎";
    if (level === "warn") return "≋";
    return "⨂";
  };
  const classFor = (level) => {
    if (level === "safe") return "safe";
    if (level === "warn") return "warn";
    return "danger";
  };

  spoofDetectionBody.innerHTML = `
    <ul class="indicator-list">
      ${spoofFindings
      .map(
        (f) => `
        <li>
          <span class="indicator-icon ${classFor(f.level)}">${iconFor(
          f.level
        )}</span>
          <div>
            <span class="indicator-label">${f.label}</span>
            <span class="indicator-extra">${f.detail}</span>
          </div>
        </li>
      `
      )
      .join("")}
    </ul>
  `;

  flagCardScanned("card-spoof-detection", 140);
}

function renderRisk(result) {
  const { score, qualitative, scoreFactors } = result;
  riskScoreValue.textContent = score.toString().padStart(2, "0");

  let labelClass = "";
  if (score <= 25) {
    labelClass = "safe";
  } else if (score <= 60) {
    labelClass = "medium";
  } else {
    labelClass = "high";
  }

  riskScoreLabel.textContent = qualitative.toUpperCase();
  riskScoreLabel.className = `risk-score-label ${labelClass}`;

  requestAnimationFrame(() => {
    riskMeterFill.style.width = `${score}%`;
  });

  riskFactorsList.innerHTML = scoreFactors
    .map((f) => `<li>${f}</li>`)
    .join("");

  flagCardScanned("card-risk-score", 200);
}

function renderSummary(result) {
  const { info, score, qualitative } = result;

  const riskWord =
    score <= 25 ? "low, but not zero" : score <= 60 ? "elevated" : "high";

  summaryBody.innerHTML = `
    <p class="summary-text">
      <span class="summary-label">Executive verdict</span>
      The scanned URL resolves to <strong>${info.hostname}</strong> over
      <strong>${info.protocol.replace(":", "").toUpperCase()}</strong>. Based on static
      heuristics, the overall risk profile is
      <strong>${riskWord}</strong> (<strong>${score}/100</strong>,
      ${qualitative.toLowerCase()}).
    </p>
    <p class="summary-text">
      This assessment looks at structure only: protocol usage, domain shape, TLD,
      path and query complexity, presence of phishing keywords, and basic spoofing
      patterns. It does <strong>not</strong> contact the remote server, execute any
      scripts, or guarantee that a link is safe or unsafe.
    </p>
    <p class="summary-text">
      Treat this output as a <strong>second opinion</strong>, not an authority:
      verify the sender, manually inspect the real destination, and when in doubt
      open suspicious content in an isolated environment or ignore it entirely.
    </p>
  `;

  flagCardScanned("card-summary", 260);
}

async function runFakeProgress() {
  setStatus("Initializing modules…", 10);
  await new Promise((r) => setTimeout(r, 220));
  setStatus("Deconstructing URL…", 32);
  await new Promise((r) => setTimeout(r, 230));
  setStatus("Checking heuristics…", 57);
  await new Promise((r) => setTimeout(r, 260));
  setStatus("Scoring risk profile…", 78);
  await new Promise((r) => setTimeout(r, 220));
  setStatus("Finalizing report…", 94);
  await new Promise((r) => setTimeout(r, 180));
  setStatus("Scan complete", 100);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const value = urlInput.value.trim();
  if (!value) {
    urlInput.focus();
    return;
  }

  scanBtn.disabled = true;

  const result = await analyzeUrl(value);
  if (result.error) {
    summaryBody.innerHTML = `<p class="summary-text"><span class="summary-label">Error</span>${result.error}</p>`;
    urlInfoBody.innerHTML = `<p class="placeholder">${result.error}</p>`;
    threatIndicatorsBody.innerHTML = `<p class="placeholder">${result.error}</p>`;
    spoofDetectionBody.innerHTML = `<p class="placeholder">${result.error}</p>`;
    riskScoreValue.textContent = "–";
    riskScoreLabel.textContent = "No data";
    riskScoreLabel.className = "risk-score-label";
    riskMeterFill.style.width = "0%";
    riskFactorsList.innerHTML = "";
    resetCards();
    flagCardScanned("card-summary");
    scanBtn.disabled = false;
    return;
  }

  resetCards();
  await runFakeProgress();

  renderUrlInfo(result);
  renderIndicators(result);
  renderSpoof(result);
  renderRisk(result);
  renderSummary(result);

  scanBtn.disabled = false;
  setTimeout(() => {
    setStatus("Idle", 0);
  }, 900);
});

