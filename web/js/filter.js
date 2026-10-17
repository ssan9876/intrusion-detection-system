/* Display filter language, modelled on Wireshark's.

   sev >= high && ip.src == 203.0.113.66
   !(status == ack) and rule contains "sql"
   port == 80 || port == 443
   tcp && len > 500
   "free text"            -> substring search across every text field

   compile(text, fields) returns { ok, fn, empty } or { ok: false, error }.
   `fields` maps a field name to { get(rec) -> value | value[], type, help, values? }.
   type is one of: str, num, ip, sev, enum, bool. Multi-valued fields (ip.addr,
   port) match when any value matches, the way Wireshark treats them.
*/
import { SEV_RANK } from "./util.js";

const OPS = {
  "==": "==", eq: "==", "!=": "!=", ne: "!=", ">": ">", gt: ">", "<": "<", lt: "<",
  ">=": ">=", ge: ">=", "<=": "<=", le: "<=", contains: "contains", matches: "matches", "~": "matches",
};

function tokenize(src) {
  const toks = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    const two = src.slice(i, i + 2);
    if (["&&", "||", "==", "!=", ">=", "<="].includes(two)) { toks.push({ t: "op", v: two, pos: i }); i += 2; continue; }
    if ("()!<>~".includes(c)) { toks.push({ t: c === "(" || c === ")" ? c : "op", v: c, pos: i }); i++; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1, s = "";
      while (j < src.length && src[j] !== c) { if (src[j] === "\\" && j + 1 < src.length) j++; s += src[j++]; }
      if (j >= src.length) throw err(`Missing closing quote ${c}`, i);
      toks.push({ t: "str", v: s, pos: i }); i = j + 1; continue;
    }
    // after `matches` / `~` the next word is a regex: keep ( ) | etc. inside it
    const prev = toks[toks.length - 1];
    if (prev && (prev.v === "~" || (prev.t === "word" && prev.v.toLowerCase() === "matches"))) {
      const r = /^\S+/.exec(src.slice(i));
      toks.push({ t: "str", v: r[0], pos: i }); i += r[0].length; continue;
    }
    const m = /^[^\s()!=<>~&|"']+/.exec(src.slice(i));
    if (!m) throw err(`Unexpected "${c}"`, i);
    toks.push({ t: "word", v: m[0], pos: i }); i += m[0].length;
  }
  return toks;
}

function err(message, pos) { const e = new Error(message); e.pos = pos; return e; }

export function compile(text, fields) {
  const src = (text || "").trim();
  if (!src) return { ok: true, empty: true, fn: () => true };
  try {
    const toks = tokenize(src);
    let k = 0;
    const peek = () => toks[k];
    const take = () => toks[k++];
    const isJoin = (t) => t.v === "&&" || (t.t === "word" && t.v.toLowerCase() === "and");
    const isOr = (t) => t.v === "||" || (t.t === "word" && t.v.toLowerCase() === "or");
    // a following term with no operator between is an implicit "and",
    // so `sql 203.0.113.66` narrows by both words
    const startsTerm = (t) => t && !isOr(t) && t.t !== ")" && (t.t !== "op" || t.v === "!");

    function orExpr() {
      let left = andExpr();
      while (peek() && isOr(peek())) {
        take(); const right = andExpr(); const l = left; left = (r) => l(r) || right(r);
      }
      return left;
    }
    function andExpr() {
      let left = notExpr();
      while (peek() && (isJoin(peek()) || startsTerm(peek()))) {
        if (isJoin(peek())) take();
        const right = notExpr(); const l = left; left = (r) => l(r) && right(r);
      }
      return left;
    }
    function notExpr() {
      if (peek() && (peek().v === "!" || (peek().t === "word" && peek().v.toLowerCase() === "not"))) {
        take(); const inner = notExpr(); return (r) => !inner(r);
      }
      return primary();
    }
    function primary() {
      const tok = take();
      if (!tok) throw err("Unexpected end of filter", src.length);
      if (tok.t === "(") {
        const e = orExpr();
        const close = take();
        if (!close || close.t !== ")") throw err("Missing closing parenthesis", close ? close.pos : src.length);
        return e;
      }
      if (tok.t === "str") return freeText(tok.v);
      if (tok.t !== "word") throw err(`Unexpected "${tok.v}"`, tok.pos);
      const name = tok.v.toLowerCase();
      const next = peek();
      const op = next && (next.t === "op" || next.t === "word") ? OPS[next.v.toLowerCase()] : undefined;
      if (op) {
        const f = fields[name];
        if (!f) throw err(`"${tok.v}" is not a valid field`, tok.pos);
        take();
        const vt = take();
        if (!vt || (vt.t !== "word" && vt.t !== "str")) throw err(`"${tok.v} ${next.v}" needs a value`, next.pos);
        return comparison(name, f, op, vt);
      }
      const f = fields[name];
      if (f) {
        if (f.shortcut) return f.shortcut;
        return (r) => { const v = f.get(r); return Array.isArray(v) ? v.some(Boolean) : Boolean(v); };
      }
      // an unknown bare word is a free-text search, so plain typing still works
      return freeText(tok.v);
    }

    function freeText(q) {
      const needle = q.toLowerCase();
      const getters = Object.values(fields).filter((f) => f.text).map((f) => f.get);
      return (r) => getters.some((g) => {
        const v = g(r);
        return (Array.isArray(v) ? v : [v]).some((x) => x != null && String(x).toLowerCase().includes(needle));
      });
    }

    function comparison(name, f, op, vt) {
      const raw = vt.v;
      let want = raw;
      if (op === "matches") {
        let re;
        try { re = new RegExp(raw, "i"); } catch { throw err(`"${raw}" is not a valid regular expression`, vt.pos); }
        return any(f, (v) => v != null && re.test(String(v)));
      }
      if (op === "contains") {
        const n = raw.toLowerCase();
        return any(f, (v) => v != null && String(v).toLowerCase().includes(n));
      }
      if (f.type === "sev") {
        want = SEV_RANK[raw.toLowerCase()];
        if (!want) throw err(`"${raw}" is not a severity (low, medium, high, critical)`, vt.pos);
        return any(f, (v) => cmp(SEV_RANK[v] || 0, op, want));
      }
      if (f.type === "num") {
        want = parseNum(raw);
        if (Number.isNaN(want)) throw err(`"${raw}" is not a number`, vt.pos);
        return any(f, (v) => v != null && cmp(Number(v), op, want));
      }
      if (f.type === "bool") {
        const b = /^(1|true|yes|on)$/i.test(raw);
        if (!/^(0|1|true|false|yes|no|on|off)$/i.test(raw)) throw err(`"${raw}" is not true or false`, vt.pos);
        return any(f, (v) => cmp(Boolean(v) ? 1 : 0, op, b ? 1 : 0));
      }
      if (f.type === "enum" && f.values && !f.values.includes(raw.toLowerCase())) {
        throw err(`"${raw}" is not valid for ${name} (${f.values.join(", ")})`, vt.pos);
      }
      if (![">", "<", ">=", "<="].includes(op)) {
        const n = raw.toLowerCase();
        return any(f, (v) => cmp(v == null ? null : String(v).toLowerCase(), op, n));
      }
      throw err(`"${op}" can't compare ${name}`, vt.pos);
    }

    const fn = orExpr();
    if (k < toks.length) {
      const t = toks[k];
      throw err(`Unexpected "${t.v}" — join conditions with && or ||`, t.pos);
    }
    return { ok: true, empty: false, fn };
  } catch (e) {
    return { ok: false, error: e.message, pos: e.pos ?? 0 };
  }
}

function parseNum(s) {
  const m = /^(\d+(?:\.\d+)?)([kmg]?)(b?)$/i.exec(s);
  if (!m) return NaN;
  const mult = { "": 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[m[2].toLowerCase()];
  return parseFloat(m[1]) * mult;
}

function any(f, test) {
  return (r) => { const v = f.get(r); return Array.isArray(v) ? v.some(test) : test(v); };
}

function cmp(a, op, b) {
  switch (op) {
    case "==": return a === b;
    case "!=": return a !== b;
    case ">": return a > b;
    case "<": return a < b;
    case ">=": return a >= b;
    case "<=": return a <= b;
    default: return false;
  }
}

/* Suggestions for the autocomplete list: field names matching the word at the caret. */
export function suggest(text, caret, fields) {
  const before = text.slice(0, caret);
  const m = /([a-z0-9_.]*)$/i.exec(before);
  const word = m ? m[1].toLowerCase() : "";
  // only suggest at the start of a term (after nothing, (, !, && or ||)
  const lead = before.slice(0, before.length - word.length).trimEnd();
  if (lead && !/(\(|!|&&|\|\||\band|\bor|\bnot)$/i.test(lead)) return { word, items: [] };
  const items = Object.entries(fields)
    .filter(([n, f]) => !f.alias && n.startsWith(word) && n !== word)
    .slice(0, 8)
    .map(([n, f]) => ({ name: n, help: f.help || "" }));
  return { word, items };
}
