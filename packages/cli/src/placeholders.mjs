import { randomBytes } from "node:crypto";

/** One random placeholder per secret per session. Leaking a placeholder reveals nothing. */
export function makePlaceholders(names) {
  const byName = new Map();
  for (const name of names) {
    byName.set(name, `rl_ph_${name}_${randomBytes(16).toString("hex")}`);
  }
  return byName;
}

function decodeBasic(value) {
  const match = /^basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(value);
  if (!match) {
    return null;
  }
  return Buffer.from(match[1], "base64").toString("utf8");
}

function headerValues(headers) {
  const values = [];
  for (const value of Object.values(headers)) {
    if (Array.isArray(value)) {
      values.push(...value);
    } else if (typeof value === "string") {
      values.push(value);
    }
  }
  return values;
}

/**
 * Returns the secret names whose placeholders appear in the request URL or headers,
 * including inside a base64 `Authorization: Basic` credential (git over HTTPS).
 */
export function detectSecrets({ url, headers }, placeholders) {
  const haystacks = [url, ...headerValues(headers)];
  const basic = typeof headers.authorization === "string" ? decodeBasic(headers.authorization) : null;
  if (basic) {
    haystacks.push(basic);
  }
  const found = new Set();
  for (const [name, placeholder] of placeholders) {
    if (haystacks.some((h) => h.includes(placeholder))) {
      found.add(name);
    }
  }
  return found;
}

function replaceAll(text, names, placeholders, values) {
  let out = text;
  for (const name of names) {
    out = out.split(placeholders.get(name)).join(values[name]);
  }
  return out;
}

/** Secret names whose placeholders appear in a decoded request body. */
export function detectInText(text, placeholders) {
  const found = new Set();
  for (const [name, placeholder] of placeholders) {
    if (text.includes(placeholder)) found.add(name);
  }
  return found;
}

const BODY_ENCODERS = {
  json: (value) => JSON.stringify(value).slice(1, -1),
  form: (value) => encodeURIComponent(value),
  text: (value) => value,
};

/** Body kind RabbitLock can rewrite safely, or null to leave the body untouched. */
export function bodyKind(contentType) {
  const type = (contentType ?? "").split(";")[0].trim().toLowerCase();
  if (type === "application/json" || type.endsWith("+json")) return "json";
  if (type === "application/x-www-form-urlencoded") return "form";
  if (type.startsWith("text/")) return "text";
  return null;
}

/** Swaps placeholders in a body, escaping each value for the body's format. */
export function substituteBody(text, kind, names, placeholders, values) {
  const encode = BODY_ENCODERS[kind];
  let out = text;
  for (const name of names) {
    out = out.split(placeholders.get(name)).join(encode(values[name]));
  }
  return out;
}

/** Swaps placeholders for real values. Only call after policy has approved every name. */
export function substituteSecrets({ url, headers }, names, placeholders, values) {
  const nextHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      nextHeaders[key] = value.map((v) => replaceAll(v, names, placeholders, values));
    } else if (typeof value === "string") {
      nextHeaders[key] = replaceAll(value, names, placeholders, values);
    }
  }
  if (typeof headers.authorization === "string") {
    const basic = decodeBasic(headers.authorization);
    if (basic) {
      const swapped = replaceAll(basic, names, placeholders, values);
      if (swapped !== basic) {
        nextHeaders.authorization = `Basic ${Buffer.from(swapped, "utf8").toString("base64")}`;
      }
    }
  }
  let nextUrl = url;
  for (const name of names) {
    nextUrl = nextUrl.split(placeholders.get(name)).join(encodeURIComponent(values[name]));
  }
  return { url: nextUrl, headers: nextHeaders };
}
