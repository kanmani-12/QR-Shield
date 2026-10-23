
const express = require("express");
const { inspectRedirectJourney } = require("./redirectAnalyzer");
const { explainRisk } = require("./riskExplainer");
const {
  scanAndRemember,
  listHistory
} = require("./threatMonitor");

const router = express.Router();

function getUrl(req) {
  const url = req.body?.url;

  if (typeof url !== "string" || url.length > 2048) {
    const error = new Error(
      "Provide a URL up to 2048 characters."
    );
    error.status = 400;
    throw error;
  }

  return url.trim();
}

router.post("/redirect-trace", async (req, res) => {
  try {
    const journey = await inspectRedirectJourney(getUrl(req));
    res.json({ ok: true, journey });
  } catch (error) {
    res.status(error.status || 400).json({
      ok: false,
      error: error.message || "Unable to trace URL."
    });
  }
});

router.post("/explain-risk", async (req, res) => {
  try {
    const risk = explainRisk(
      getUrl(req),
      req.body?.journey || null
    );

    res.json({ ok: true, risk });
  } catch (error) {
    res.status(error.status || 400).json({
      ok: false,
      error: error.message || "Unable to analyze URL."
    });
  }
});

router.post("/scan", async (req, res) => {
  try {
    const result = await scanAndRemember(getUrl(req));
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.status || 400).json({
      ok: false,
      error: error.message || "Scan failed."
    });
  }
});

router.get("/history", async (_req, res) => {
  try {
    res.json({
      ok: true,
      history: await listHistory()
    });
  } catch {
    res.status(500).json({
      ok: false,
      error: "Could not read scan history."
    });
  }
});

module.exports = router;
