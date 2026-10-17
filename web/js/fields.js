/* Display-filter field definitions for each view (see filter.js). */
import { isInternal } from "./util.js";

const now = () => Date.now() / 1000;
const proto = (p) => ({ type: "bool", get: (r) => r.proto === p, help: `${p.toUpperCase()} only` });

const ipFields = (src = (r) => r.src, dst = (r) => r.dst) => ({
  "ip.src": { type: "ip", get: src, text: true, help: "Source address" },
  "ip.dst": { type: "ip", get: dst, text: true, help: "Destination address" },
  "ip.addr": { type: "ip", get: (r) => [src(r), dst(r)], help: "Source or destination address" },
  "ip.src.internal": { type: "bool", get: (r) => isInternal(src(r)), help: "Source is on a private network" },
  "ip.dst.internal": { type: "bool", get: (r) => isInternal(dst(r)), help: "Destination is on a private network" },
});

const portFields = {
  port: { type: "num", get: (r) => [r.sport, r.dport], text: true, help: "Source or destination port" },
  sport: { type: "num", get: (r) => r.sport, help: "Source port" },
  dport: { type: "num", get: (r) => r.dport, help: "Destination port" },
  "tcp.port": { type: "num", get: (r) => (r.proto === "tcp" ? [r.sport, r.dport] : null), help: "TCP port, either side" },
  "udp.port": { type: "num", get: (r) => (r.proto === "udp" ? [r.sport, r.dport] : null), help: "UDP port, either side" },
};

const protoFields = {
  proto: { type: "enum", values: ["tcp", "udp", "icmp", "ip"], get: (r) => r.proto, help: "tcp, udp, icmp or ip" },
  tcp: proto("tcp"), udp: proto("udp"), icmp: proto("icmp"),
};

export const alertFields = {
  "alert.id": { type: "num", get: (r) => r.id, help: "Alert number (No. column)" },
  sev: { type: "sev", get: (r) => r.severity, help: "Severity: low < medium < high < critical" },
  severity: { type: "sev", get: (r) => r.severity, alias: true },
  status: { type: "enum", values: ["new", "ack", "fp", "muted"], get: (r) => r.status, help: "new, ack, fp (false positive) or muted" },
  ...ipFields(),
  ...portFields,
  ...protoFields,
  "rule.id": { type: "str", get: (r) => r.rule_id, text: true, help: "Signature id, e.g. WEB-SQLI-UNION" },
  rule: { type: "str", get: (r) => r.rule_id, alias: true },
  "rule.name": { type: "str", get: (r) => r.rule_name, text: true, help: "Signature name" },
  category: { type: "str", get: (r) => r.category, text: true, help: "malware, exploit, web-attack, recon, c2, policy" },
  detail: { type: "str", get: (r) => r.detail, text: true, help: "Detection detail / payload preview" },
  age: { type: "num", get: (r) => now() - r.ts, help: "Seconds since the alert, e.g. age < 3600" },
};

export const packetFields = {
  ...ipFields(),
  ...portFields,
  ...protoFields,
  len: { type: "num", get: (r) => r.length, help: "Frame length in bytes" },
  "frame.len": { type: "num", get: (r) => r.length, alias: true },
  info: { type: "str", get: (r) => r.summary, text: true, help: "Summary line" },
  age: { type: "num", get: (r) => now() - r.ts, help: "Seconds since capture" },
};

export const flowFields = {
  ...ipFields(),
  ...protoFields,
  packets: { type: "num", get: (r) => r.packets, help: "Packets in the conversation" },
  bytes: { type: "num", get: (r) => r.bytes, help: "Bytes in the conversation (accepts 10k, 2m)" },
  duration: { type: "num", get: (r) => r.last_seen - r.first_seen, help: "Seconds between first and last packet" },
};

export const hostFields = {
  "ip.addr": { type: "ip", get: (r) => r.host, text: true, help: "Host address" },
  host: { type: "ip", get: (r) => r.host, alias: true },
  internal: { type: "bool", get: (r) => r.internal, help: "On a private network" },
  packets: { type: "num", get: (r) => r.packets, help: "Packets sent + received" },
  bytes: { type: "num", get: (r) => r.bytes, help: "Bytes sent + received (accepts 10k, 2m)" },
  "tx.bytes": { type: "num", get: (r) => r.bytes_tx, help: "Bytes sent" },
  "rx.bytes": { type: "num", get: (r) => r.bytes_rx, help: "Bytes received" },
  peers: { type: "num", get: (r) => r.peers, help: "Distinct hosts talked to" },
  ports: { type: "num", get: (r) => r.ports, help: "Distinct destination ports contacted" },
  alerts: { type: "num", get: (r) => r.as_src + r.as_dst, help: "Alerts as source or target today" },
  untriaged: { type: "num", get: (r) => r.untriaged, help: "Untriaged alerts raised by this host" },
};

export const ruleFields = {
  "rule.id": { type: "str", get: (r) => r.id, text: true, help: "Signature id" },
  rule: { type: "str", get: (r) => r.id, alias: true },
  "rule.name": { type: "str", get: (r) => r.name, text: true, help: "Signature name" },
  sev: { type: "sev", get: (r) => r.severity, help: "Severity: low < medium < high < critical" },
  category: { type: "str", get: (r) => r.category, text: true, help: "Signature category" },
  proto: { type: "str", get: (r) => r.protocol, help: "tcp, udp, icmp, ip or any" },
  enabled: { type: "bool", get: (r) => r.enabled, help: "Signature is active" },
  muted: { type: "bool", get: (r) => Boolean(r.muted_until), help: "Alerts are muted for now" },
  hits: { type: "num", get: (r) => r.hits, help: "Alerts raised, all time" },
  hits24: { type: "num", get: (r) => r.hits_24h, help: "Alerts raised in the last 24 h" },
  match: { type: "str", get: (r) => r.content || r.content_hex || r.regex || "", text: true, help: "Content / hex / regex the rule looks for" },
  dport: { type: "num", get: (r) => r.dst_port, help: "Destination port the rule is limited to" },
};
