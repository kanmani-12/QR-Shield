
const { validatePublicHttpUrl } = require("./urlSafety");

async function inspectRedirectJourney(inputUrl) {
  let current = await validatePublicHttpUrl(inputUrl);
  const hops = [];
  const visited = new Set();
  const maxRedirects = 8;

  for (let i = 0; i <= maxRedirects; i++) {
    const currentUrl = current.href;

    if (visited.has(currentUrl)) {
      hops.push({
        url: currentUrl,
        status: null,
        note: "Redirect loop detected"
      });
      break;
    }

    visited.add(currentUrl);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 7000);

    let response;

    try {
      response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "QRShield-Research-Scanner/1.0"
        }
      });
    } catch (error) {
      hops.push({
        url: currentUrl,
        status: null,
        note: error.name === "AbortError"
          ? "Request timed out"
          : "Could not fetch URL"
      });
      break;
    } finally {
      clearTimeout(timeout);
    }

    const hop = {
      url: currentUrl,
      status: response.status,
      note: "Visited URL"
    };

    hops.push(hop);

    const location = response.headers.get("location");
    const isRedirect = [301, 302, 303, 307, 308]
      .includes(response.status);

    if (isRedirect && location) {
      if (i === maxRedirects) {
        hop.note = "Maximum redirect limit reached";
        try { await response.body?.cancel(); } catch {}
        break;
      }

      try {
        const next = new URL(location, current);
        current = await validatePublicHttpUrl(next.href);
        hop.note = `Redirects to ${current.hostname}`;
      } catch (error) {
        hop.note = `Redirect blocked: ${error.message}`;
        try { await response.body?.cancel(); } catch {}
        break;
      }

      try { await response.body?.cancel(); } catch {}
      continue;
    }

    try { await response.body?.cancel(); } catch {}
    break;
  }

  return {
    inputUrl,
    finalUrl: hops.length
      ? hops[hops.length - 1].url
      : inputUrl,
    redirectCount: Math.max(0, hops.length - 1),
    hops,
    checkedAt: new Date().toISOString()
  };
}

module.exports = { inspectRedirectJourney };
