
const dns = require("node:dns/promises");
const net = require("node:net");
const ipaddr = require("ipaddr.js");

function isBlockedAddress(address) {
  try {
    return ipaddr.parse(address).range() !== "unicast";
  } catch {
    return true;
  }
}

async function validatePublicHttpUrl(rawUrl) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are allowed.");
  }

  if (url.username || url.password) {
    throw new Error("URLs containing credentials are blocked.");
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (
    !hostname ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error("Local and internal hostnames are blocked.");
  }

  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) {
      throw new Error("Private or reserved IP blocked.");
    }
  } else {
    let records;

    try {
      records = await dns.lookup(hostname, {
        all: true,
        verbatim: true
      });
    } catch {
      throw new Error("Domain could not be resolved.");
    }

    if (
      !records.length ||
      records.some(record => isBlockedAddress(record.address))
    ) {
      throw new Error("Domain resolves to a private or reserved IP.");
    }
  }

  return url;
}

module.exports = { validatePublicHttpUrl };
