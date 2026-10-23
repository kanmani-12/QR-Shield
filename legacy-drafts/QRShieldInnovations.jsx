
import { useEffect, useState } from "react";
import {
  traceRedirects,
  explainRisk,
  scanAndRemember,
  fetchThreatHistory
} from "./api";
import "./qrshield.css";

export function QRShieldInnovations() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [journey, setJourney] = useState(null);
  const [risk, setRisk] = useState(null);
  const [history, setHistory] = useState([]);
  const [monitor, setMonitor] = useState(null);
  const [tab, setTab] = useState("trace");

  async function loadHistory() {
    try {
      setHistory(await fetchThreatHistory());
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => {
    loadHistory();
  }, []);

  async function runTrace() {
    setBusy(true);
    setError("");
    setMonitor(null);

    try {
      const result = await traceRedirects(url.trim());
      setJourney(result.journey);

      const riskResult = await explainRisk(
        url.trim(),
        result.journey
      );

      setRisk(riskResult.risk);
      setTab("trace");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function runMonitorScan() {
    setBusy(true);
    setError("");

    try {
      const result = await scanAndRemember(url.trim());

      setJourney(result.journey);
      setRisk(result.risk);
      setMonitor(result.monitor);

      await loadHistory();
      setTab("monitor");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="qs-wrap">
      <header className="qs-header">
        <p className="qs-eyebrow">QRSHIELD SECURITY</p>
        <h2>Link Intelligence Lab</h2>
        <p className="qs-muted">
          Trace redirects, understand risk and compare scans.
        </p>
      </header>

      <form
        className="qs-input-row"
        onSubmit={e => {
          e.preventDefault();
          runTrace();
        }}
      >
        <input
          type="url"
          required
          maxLength={2048}
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="https://example.com"
          aria-label="Website URL"
        />

        <button disabled={busy || !url.trim()}>
          {busy ? "Checking..." : "Trace & Explain"}
        </button>

        <button
          type="button"
          disabled={busy || !url.trim()}
          onClick={runMonitorScan}
        >
          Save / Recheck
        </button>
      </form>

      {error && <p className="qs-error">{error}</p>}

      <nav className="qs-tabs">
        <button onClick={() => setTab("trace")}>
          Redirect Journey
        </button>
        <button onClick={() => setTab("risk")}>
          Risk Explanation
        </button>
        <button onClick={() => setTab("monitor")}>
          Threat Monitor
        </button>
      </nav>

      {tab === "trace" && (
        <div className="qs-card">
          <h3>Redirect Journey</h3>

          {!journey ? (
            <p>Enter a URL to start scanning.</p>
          ) : (
            <>
              <ol className="qs-journey">
                {journey.hops.map((hop, index) => (
                  <li key={`${hop.url}-${index}`}>
                    <strong>Step {index + 1}</strong>
                    <p className="qs-url">{hop.url}</p>
                    <p>
                      {hop.status
                        ? `HTTP ${hop.status}`
                        : "No HTTP status"}
                      {" — "}
                      {hop.note}
                    </p>
                  </li>
                ))}
              </ol>
              <p>
                Redirects observed: {journey.redirectCount}
              </p>
            </>
          )}
        </div>
      )}

      {tab === "risk" && (
        <div className="qs-card">
          <h3>Explainable Risk Assessment</h3>

          {!risk ? (
            <p>Run Trace & Explain first.</p>
          ) : (
            <>
              <h2>
                {risk.level.toUpperCase()} — {risk.score}/100
              </h2>
              <p>Confidence: {risk.confidence}</p>

              {risk.reasons.length === 0 ? (
                <p>
                  No configured warning indicators were found.
                  This does not guarantee safety.
                </p>
              ) : (
                <ul>
                  {risk.reasons.map(reason => (
                    <li key={reason.code}>
                      <strong>{reason.code.replaceAll("_", " ")}</strong>
                      {" — "}
                      {reason.severity}
                      <p>{reason.explanation}</p>
                    </li>
                  ))}
                </ul>
              )}

              <p className="qs-muted">
                {risk.disclaimer ||
                  "This is a heuristic assessment, not a safety guarantee."}
              </p>
            </>
          )}
        </div>
      )}

      {tab === "monitor" && (
        <div className="qs-card">
          <h3>Threat Change Monitor</h3>
          <p>
            Click Save / Recheck to compare the new scan
            with the previous scan for the same URL.
          </p>

          {monitor && (
            <div>
              {!monitor.change ? (
                <p>First scan saved successfully.</p>
              ) : (
                <>
                  <p>
                    Risk score: {monitor.change.previousRiskScore}
                    {" → "}
                    {monitor.riskScore}
                  </p>
                  <p>
                    Score change: {monitor.change.scoreDelta > 0
                      ? "+"
                      : ""}
                    {monitor.change.scoreDelta}
                  </p>
                  <p>
                    Risk level changed:{" "}
                    {monitor.change.riskLevelChanged ? "Yes" : "No"}
                  </p>
                  <p>
                    Destination changed:{" "}
                    {monitor.change.destinationChanged ? "Yes" : "No"}
                  </p>
                </>
              )}
            </div>
          )}

          <h4>Recent scans</h4>

          {history.length === 0 ? (
            <p>No saved scans yet.</p>
          ) : (
            history.slice(0, 20).map(item => (
              <article key={item.id} className="qs-history-item">
                <strong>
                  {item.riskLevel.toUpperCase()} — {item.riskScore}/100
                </strong>
                <p className="qs-url">{item.inputUrl}</p>
                <small>
                  {new Date(item.checkedAt).toLocaleString()}
                </small>
              </article>
            ))
          )}
        </div>
      )}
    </section>
  );
}
