
const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

async function post(path, body) {
  const response = await fetch(
    `${API_BASE}/api/qrshield${path}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json();

  if (!response.ok || !data.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

export const traceRedirects = url =>
  post("/redirect-trace", { url });

export const explainRisk = (url, journey) =>
  post("/explain-risk", { url, journey });

export const scanAndRemember = url =>
  post("/scan", { url });

export async function fetchThreatHistory() {
  const response = await fetch(
    `${API_BASE}/api/qrshield/history`
  );

  const data = await response.json();

  if (!response.ok || !data.ok) {
    throw new Error(data.error || "Could not load history.");
  }

  return data.history;
}
