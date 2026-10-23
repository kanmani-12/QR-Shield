
const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy"
]);

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "click", "top", "xyz", "work"
]);

function explainRisk(rawUrl, journey = null) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    return {
      score: 100,
      level: "high",
      confidence: "high",
      reasons: [{
        code: "INVALID_URL",
        severity: "high",
        explanation: "The URL format is invalid."
      }]
    };
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const reasons = [];

  function add(code, severity, points, explanation) {
    reasons.push({ code, severity, points, explanation });
  }

  if (url.protocol !== "https:") {
    add(
      "NO_HTTPS", "medium", 15,
      "The URL does not use HTTPS. This alone does not prove phishing."
    );
  }

  if (labels.some(label => label.startsWith("xn--"))) {
    add(
      "PUNYCODE", "high", 25,
      "The domain uses punycode, which can occur in lookalike domains."
    );
  }

  if (SHORTENERS.has(host)) {
    add(
      "URL_SHORTENER", "medium", 12,
      "A URL-shortening service hides the destination."
    );
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    add(
      "UNCOMMON_TLD", "low", 8,
      "This top-level domain can be abused, but is not proof of risk."
    );
  }

  if (labels.length >= 5) {
    add(
      "MANY_SUBDOMAINS", "medium", 10,
      "The hostname has many subdomains. Check the actual registered domain."
    );
  }

  if (["login", "verify", "secure", "account"]
    .some(word => host.includes(word))) {
    add(
      "SENSITIVE_KEYWORDS", "low", 8,
      "The hostname contains login-related words."
    );
  }

  if (url.href.length > 180) {
    add(
      "LONG_URL", "medium", 10,
      "The URL is unusually long and should be reviewed."
    );
  }

  if (journey?.redirectCount > 0) {
    add(
      "REDIRECT_CHAIN",
      journey.redirectCount >= 4 ? "high" : "medium",
      journey.redirectCount >= 4 ? 20 : 8,
      `The scan observed ${journey.redirectCount} redirect(s).`
    );
  }

  if (journey?.hops?.some(hop =>
    (hop.note || "").startsWith("Redirect blocked:")
  )) {
    add(
      "BLOCKED_REDIRECT", "high", 30,
      "A redirect destination was blocked by the scanner's safety policy."
    );
  }

  const score = Math.min(
    100,
    reasons.reduce((total, item) => total + item.points, 0)
  );

  const level =
    score >= 45 ? "high" :
    score >= 20 ? "caution" : "low";

  return {
    score,
    level,
    confidence: reasons.length >= 3 ? "medium" : "low",
    reasons,
    disclaimer:
      "Heuristic result only. A low score does not guarantee a safe website."
  };
}

module.exports = { explainRisk };
