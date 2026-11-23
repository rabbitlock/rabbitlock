import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";

import { bodyKind, detectInText, detectSecrets, substituteBody, substituteSecrets } from "./placeholders.mjs";
import { hostMatches, interceptHosts, secretAllowedForHost } from "./policy.mjs";

const HOP_BY_HOP = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function stripHopByHop(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      out[key] = value;
    }
  }
  return out;
}

export function parseHostPort(authority, defaultPort) {
  const ipv6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(authority);
  if (ipv6) {
    return { host: ipv6[1].toLowerCase(), port: Number(ipv6[2] ?? defaultPort) };
  }
  const idx = authority.lastIndexOf(":");
  if (idx > -1 && /^\d+$/.test(authority.slice(idx + 1))) {
    return { host: authority.slice(0, idx).toLowerCase(), port: Number(authority.slice(idx + 1)) };
  }
  return { host: authority.toLowerCase(), port: defaultPort };
}

/**
 * Test-only routing: RABBITLOCK_TEST_UPSTREAM="host=127.0.0.1:8443,other=127.0.0.1:8443"
 * and RABBITLOCK_TEST_UPSTREAM_CA=<pem file>. TLS identity is still checked against the
 * original host name.
 */
function loadTestRouting() {
  const routes = new Map();
  for (const pair of (process.env.RABBITLOCK_TEST_UPSTREAM ?? "").split(",").filter(Boolean)) {
    const [host, target] = pair.split("=");
    routes.set(host.toLowerCase(), parseHostPort(target, 443));
  }
  const caFile = process.env.RABBITLOCK_TEST_UPSTREAM_CA;
  return { routes, ca: caFile ? fs.readFileSync(caFile, "utf8") : undefined };
}

export const MAX_BODY_BYTES = 1024 * 1024;

/**
 * Reads up to `limit` bytes of the request body. Returns the chunks read and whether the whole
 * body fit. If it did not fit, the caller forwards the chunks and then streams the remainder.
 */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const onData = (chunk) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size > limit) {
        cleanup();
        req.pause();
        resolve({ chunks, complete: false });
      }
    };
    const onEnd = () => {
      cleanup();
      resolve({ chunks, complete: true });
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      req.off("data", onData);
      req.off("end", onEnd);
      req.off("error", onError);
    };
    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
  });
}

function pathWithoutQuery(url) {
  const idx = url.indexOf("?");
  return idx === -1 ? url : url.slice(0, idx);
}

function deny(res, status, message) {
  if (!res.headersSent) {
    res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "x-rabbitlock": "denied" });
  }
  res.end(`RabbitLock: ${message}\n`);
}

/**
 * Starts the local broker proxy.
 *
 * - CONNECT to a host listed in policy: TLS is terminated with a leaf cert from the local CA,
 *   placeholders are swapped for real values only if policy + approval allow, then the request
 *   is re-sent upstream over verified TLS.
 * - CONNECT to any other host: opaque TCP tunnel. Such traffic can only ever carry placeholders.
 * - Plain HTTP: forwarded, but never injected (real secrets are not sent in cleartext).
 */
export async function startProxy({ policy, placeholders, values, contextFor, approvalGate, receipt }) {
  const intercepted = interceptHosts(policy);
  const shouldIntercept = (host) => intercepted.some((pattern) => hostMatches(pattern, host));
  const routing = loadTestRouting();
  const targets = new WeakMap();

  function forward(req, res, { protocol, host, port, url, headers, secrets, body }) {
    const route = routing.routes.get(host);
    const transport = protocol === "https" ? https : http;
    const upstream = transport.request(
      {
        host: route?.host ?? host,
        port: route?.port ?? port,
        method: req.method,
        path: url,
        headers: stripHopByHop(headers),
        servername: protocol === "https" && !net.isIP(host) ? host : undefined,
        ca: protocol === "https" ? routing.ca : undefined,
        agent: false,
      },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, stripHopByHop(upRes.headers));
        upRes.pipe(res);
        if (secrets.length > 0) {
          receipt({ secrets, host, method: req.method, path: pathWithoutQuery(req.url), decision: "injected", status: upRes.statusCode });
        }
      },
    );
    upstream.on("error", (err) => {
      if (secrets.length > 0) {
        receipt({ secrets, host, method: req.method, path: pathWithoutQuery(req.url), decision: "upstream_error", error: err.code ?? "error" });
      }
      deny(res, 502, `upstream ${host} failed (${err.code ?? err.message})`);
    });
    if (!body) {
      req.pipe(upstream);
    } else if (body.complete) {
      upstream.end(Buffer.concat(body.chunks));
    } else {
      for (const chunk of body.chunks) upstream.write(chunk);
      req.pipe(upstream);
      req.resume();
    }
  }

  async function handle(req, res, target) {
    const { protocol, host, port } = target;
    const names = new Set(detectSecrets({ url: req.url, headers: req.headers }, placeholders));

    // Bodies are only buffered for formats we can rewrite safely and when not compressed.
    const kind = bodyKind(req.headers["content-type"]);
    const encoded = req.headers["content-encoding"] && req.headers["content-encoding"] !== "identity";
    let body = null;
    let bodyNames = new Set();
    if (kind && !encoded && req.method !== "GET" && req.method !== "HEAD") {
      body = await readBody(req, MAX_BODY_BYTES);
      if (body.complete) {
        bodyNames = detectInText(Buffer.concat(body.chunks).toString("utf8"), placeholders);
        for (const name of bodyNames) names.add(name);
      }
    }
    return decide(req, res, target, [...names], body, kind, bodyNames);
  }

  async function decide(req, res, target, names, body, kind, bodyNames) {
    const { protocol, host, port } = target;
    const base = { secrets: names, host, method: req.method, path: pathWithoutQuery(req.url) };

    if (names.length > 0) {
      if (protocol !== "https") {
        receipt({ ...base, decision: "blocked_insecure" });
        return deny(res, 403, "secrets are only injected over HTTPS");
      }
      const disallowed = names.filter((name) => !secretAllowedForHost(policy.secrets[name], host));
      if (disallowed.length > 0) {
        receipt({ ...base, decision: "blocked_host", blocked: disallowed });
        return deny(res, 403, `${disallowed.join(", ")} is not allowed for host ${host}`);
      }
      const approval = await approvalGate(names, { host, method: req.method, path: base.path });
      if (!approval.ok) {
        receipt({ ...base, decision: "denied_approval", blocked: [approval.secret] });
        return deny(res, 403, `use of ${approval.secret} was not approved`);
      }
    }

    const swapped = names.length > 0
      ? substituteSecrets({ url: req.url, headers: req.headers }, names, placeholders, values)
      : { url: req.url, headers: req.headers };

    if (body?.complete && bodyNames.size > 0) {
      const rewritten = Buffer.from(
        substituteBody(Buffer.concat(body.chunks).toString("utf8"), kind, [...bodyNames], placeholders, values),
        "utf8",
      );
      body = { chunks: [rewritten], complete: true };
      swapped.headers = { ...swapped.headers, "content-length": String(rewritten.length) };
    } else if (body?.complete) {
      swapped.headers = { ...swapped.headers, "content-length": String(Buffer.concat(body.chunks).length) };
    }

    forward(req, res, { protocol, host, port, url: swapped.url, headers: swapped.headers, secrets: names, body });
  }

  // Requests arriving inside intercepted TLS tunnels.
  const mitm = http.createServer((req, res) => {
    const target = targets.get(req.socket);
    if (!target) return deny(res, 500, "lost tunnel target");
    handle(req, res, target).catch((err) => deny(res, 500, err.message));
  });

  // Plain-HTTP proxy requests (absolute-form URLs).
  const server = http.createServer((req, res) => {
    let parsed;
    try {
      parsed = new URL(req.url);
    } catch {
      return deny(res, 400, "expected an absolute URL (this is a proxy)");
    }
    const { host, port } = parseHostPort(parsed.host, 80);
    const path = `${parsed.pathname}${parsed.search}`;
    req.url = path;
    handle(req, res, { protocol: "http", host, port }).catch((err) => deny(res, 500, err.message));
  });

  server.on("connect", (req, clientSocket, head) => {
    const { host, port } = parseHostPort(req.url, 443);
    clientSocket.on("error", () => clientSocket.destroy());

    if (shouldIntercept(host)) {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) clientSocket.unshift(head);
      const tlsSocket = new tls.TLSSocket(clientSocket, {
        isServer: true,
        secureContext: contextFor(host),
        ALPNProtocols: ["http/1.1"],
      });
      tlsSocket.on("error", () => tlsSocket.destroy());
      targets.set(tlsSocket, { protocol: "https", host, port });
      mitm.emit("connection", tlsSocket);
      return;
    }

    const route = routing.routes.get(host);
    const upstream = net.connect(route?.port ?? port, route?.host ?? host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on("error", () => {
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        mitm.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
