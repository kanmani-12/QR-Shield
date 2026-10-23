
const fs = require("node:fs/promises");
const path = require("node:path");
const { inspectRedirectJourney } = require("./redirectAnalyzer");
const { explainRisk } = require("./riskExplainer");

const dataDir = path.join(__dirname, "data");
const storeFile = path.join(dataDir, "threat-history.json");

async function readHistory() {
  try {
    const data = await fs.readFile(storeFile, "utf8");
    return JSON.parse(data);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function saveHistory(history) {
  await fs.mkdir(dataDir, { recursive: true });
  await fs.writeFile(
    storeFile,
    JSON.stringify(history, null, 2),
    "utf8"
  );
}

async function scanAndRemember(rawUrl) {
  const journey = await inspectRedirectJourney(rawUrl);
  const risk = explainRisk(rawUrl, journey);
  const history = await readHistory();

  const previous = history.find(
    item => item.inputUrl === journey.inputUrl
  );

  const monitor = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    inputUrl: journey.inputUrl,
    finalUrl: journey.finalUrl,
    riskScore: risk.score,
    riskLevel: risk.level,
    redirectCount: journey.redirectCount,
    checkedAt: journey.checkedAt,
    change: previous ? {
      previousRiskScore: previous.riskScore,
      scoreDelta: risk.score - previous.riskScore,
      destinationChanged: previous.finalUrl !== journey.finalUrl,
      riskLevelChanged: previous.riskLevel !== risk.level
    } : null
  };

  history.unshift(monitor);
  await saveHistory(history.slice(0, 500));

  return { journey, risk, monitor };
}

async function listHistory() {
  return readHistory();
}

module.exports = { scanAndRemember, listHistory };
