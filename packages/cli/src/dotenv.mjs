/**
 * Minimal .env parser for `rabbitlock import`. Supports the common forms:
 *   KEY=value            unquoted; trailing " # comment" removed; surrounding whitespace trimmed
 *   export KEY=value     leading `export` ignored
 *   KEY="value"          escapes \n \r \t \" \\ ; may span multiple lines (for PEM keys)
 *   KEY='value'          literal; may span multiple lines
 *   # comment, blank lines
 * Returns entries in file order (later duplicates win) and the line numbers it couldn't parse.
 * Never includes values in errors.
 */
export function parseDotenv(text) {
  const entries = new Map();
  const errors = [];
  const lines = text.replace(/\r\n?/g, "\n").split("\n");

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const line = lines[i].trim();
    if (line === "" || line.startsWith("#")) continue;

    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!match) {
      errors.push({ line: lineNo, reason: "not KEY=VALUE" });
      continue;
    }
    const [, key, rest] = match;
    const quote = rest[0];

    if (quote === '"' || quote === "'") {
      let body = rest.slice(1);
      let closed = findClosingQuote(body, quote);
      let j = i;
      while (closed === -1 && j + 1 < lines.length) {
        j += 1;
        body += `\n${lines[j]}`;
        closed = findClosingQuote(body, quote);
      }
      if (closed === -1) {
        errors.push({ line: lineNo, reason: "unterminated quote" });
        continue;
      }
      const after = body.slice(closed + 1).trim();
      if (after !== "" && !after.startsWith("#")) {
        errors.push({ line: lineNo, reason: "unexpected text after closing quote" });
        i = j;
        continue;
      }
      const raw = body.slice(0, closed);
      entries.set(key, quote === '"' ? unescapeDouble(raw) : raw);
      i = j;
      continue;
    }

    const value = rest.replace(/\s+#.*$/, "").trim();
    entries.set(key, value);
  }

  return { entries: [...entries], errors };
}

function findClosingQuote(body, quote) {
  for (let k = 0; k < body.length; k += 1) {
    if (quote === '"' && body[k] === "\\") {
      k += 1;
      continue;
    }
    if (body[k] === quote) return k;
  }
  return -1;
}

function unescapeDouble(raw) {
  return raw.replace(/\\([nrt"\\])/g, (_, ch) => ({ n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" })[ch]);
}
