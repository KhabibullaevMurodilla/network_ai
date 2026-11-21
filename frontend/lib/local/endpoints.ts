/** External connection summary from a capture, in the browser. Port of
 *  backend/app/ingestion/endpoints.py (extract_endpoints, parse_sni): per
 *  (remote public IP, remote port, proto) packets/bytes/flows plus hostnames
 *  learned passively from DNS A answers and TLS ClientHello SNI. The DNS
 *  decoder is deliberately as strict as dpkt's: one malformed or unsupported
 *  record (e.g. HTTPS/RRSIG types) discards the whole response, as in Python. */
import { iterPackets, decodeEthernet, decodeStrict, isPrivate, isPublic, u16 } from "./netdecode";

export interface EndpointRow {
  remote_ip: string;
  remote_port: number;
  proto: "tcp" | "udp";
  packets: number;
  bytes_out: number;
  bytes_in: number;
  first_ts: number;
  last_ts: number;
  flows: number;
  hostnames: string[];
}

const NAME_RE = /^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$/;
const MAX_NAMES = 8;

// Python str.isspace() characters (str.strip() with no argument)
const PY_SPACE = new Set<number>([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

function pyStrip(s: string): string {
  let a = 0, b = s.length;
  while (a < b && PY_SPACE.has(s.charCodeAt(a))) a++;
  while (b > a && PY_SPACE.has(s.charCodeAt(b - 1))) b--;
  return s.slice(a, b);
}

function cleanName(n: string | null): string | null {
  if (!n) return null;
  let s = pyStrip(n);
  let a = 0, b = s.length;
  while (a < b && s[a] === ".") a++;
  while (b > a && s[b - 1] === ".") b--;
  s = s.slice(a, b).toLowerCase();
  return NAME_RE.test(s) ? s : null;
}

/** Server name from a TLS ClientHello, or null. Never throws. */
export function parseSni(p: Uint8Array): string | null {
  const at = (i: number): number => { if (i < 0 || i >= p.length) throw new RangeError("oob"); return p[i]; };
  const word = (i: number): number => { if (i < 0 || i + 2 > p.length) throw new RangeError("oob"); return u16(p, i); };
  try {
    if (p.length < 48 || p[0] !== 0x16 || p[5] !== 0x01) return null;
    let i = 5 + 4 + 2 + 32;            // record hdr, handshake hdr, version, random
    i += 1 + at(i);                    // session id
    i += 2 + word(i);                  // cipher suites
    i += 1 + at(i);                    // compression methods
    const end = i + 2 + word(i);
    i += 2;
    while (i + 4 <= Math.min(end, p.length)) {
      const etype = u16(p, i), elen = u16(p, i + 2);
      if (etype === 0) {               // server_name: list_len(2) name_type(1) name_len(2) name
        const nlen = word(i + 7);
        const raw = p.subarray(i + 9, i + 9 + nlen);
        let s = "";
        for (let k = 0; k < raw.length; k++) if (raw[k] < 0x80) s += String.fromCharCode(raw[k]); // ascii/ignore
        return cleanName(s);
      }
      i += 4 + elen;
    }
  } catch {
    return null;
  }
  return null;
}

// ---- dpkt.dns equivalent (strict) ------------------------------------------
function unpackName(buf: Uint8Array, off: number): [string, number] {
  const labels: Uint8Array[] = [];
  let saved = 0, start = off, total = 0;
  for (;;) {
    if (off >= buf.length) throw new Error("NeedData");
    const n = buf[off];
    if (n === 0) { off += 1; break; }
    else if ((n & 0xc0) === 0xc0) {
      if (off + 2 > buf.length) throw new Error("short pointer");
      const ptr = u16(buf, off) & 0x3fff;
      if (ptr >= start) throw new Error("Invalid label compression pointer");
      off += 2;
      if (!saved) saved = off;
      start = off = ptr;
    } else if ((n & 0xc0) === 0x00) {
      off += 1;
      labels.push(buf.subarray(off, off + n));
      total += n + 1;
      if (total > 255) throw new Error("name longer than 255 bytes");
      off += n;
    } else throw new Error("Invalid label length");
  }
  if (!saved) saved = off;
  let len = Math.max(labels.length - 1, 0);
  for (const l of labels) len += l.length;
  const joined = new Uint8Array(len);
  let o = 0;
  labels.forEach((l, i) => { if (i) joined[o++] = 0x2e; joined.set(l, o); o += l.length; });
  return [decodeStrict(joined), saved];
}

interface DnsRR { type: number; rdata: Uint8Array }
interface DnsMsg { qr: boolean; qd: string[]; an: DnsRR[] }

function unpackRdata(buf: Uint8Array, off: number, type: number, rdata: Uint8Array): void {
  switch (type) {
    case 1: case 28: case 10: case 41: return;            // A, AAAA, NULL, OPT: kept raw
    case 2: case 5: case 12: unpackName(buf, off); return; // NS, CNAME, PTR
    case 6: {                                              // SOA
      let r = unpackName(buf, off);
      r = unpackName(buf, r[1]);
      if (buf.length - r[1] < 20) throw new Error("short SOA"); // struct '>IIIII' on buf[off:off+20]
      return;
    }
    case 15:                                               // MX
      if (rdata.length < 2) throw new Error("short MX");
      unpackName(buf, off + 2);
      return;
    case 13: case 16: {                                    // HINFO, TXT: length-prefixed strict utf-8
      let b = rdata;
      while (b.length) { const n = b[0]; decodeStrict(b.subarray(1, 1 + n)); b = b.subarray(1 + n); }
      return;
    }
    case 33:                                               // SRV
      if (rdata.length < 6) throw new Error("short SRV");
      unpackName(buf, off + 6);
      return;
    default:
      throw new Error("RR type not supported");
  }
}

function parseDns(buf: Uint8Array): DnsMsg {
  if (buf.length < 12) throw new Error("short dns");
  const op = u16(buf, 2);
  const counts = [u16(buf, 4), u16(buf, 6), u16(buf, 8), u16(buf, 10)];
  let off = 12;
  const qd: string[] = [];
  for (let k = 0; k < counts[0]; k++) {
    const [name, o2] = unpackName(buf, off);
    if (buf.length - o2 < 4) throw new Error("short question");
    off = o2 + 4;
    qd.push(name);
  }
  const an: DnsRR[] = [];
  for (let sec = 1; sec < 4; sec++) {
    for (let k = 0; k < counts[sec]; k++) {
      const [, o2] = unpackName(buf, off);
      if (buf.length - o2 < 10) throw new Error("short rr");
      const type = u16(buf, o2);
      const rdlen = u16(buf, o2 + 8);
      off = o2 + 10;
      const rdata = buf.subarray(off, off + rdlen);
      unpackRdata(buf, off, type, rdata);
      off += rdlen;
      if (sec === 1) an.push({ type, rdata });
    }
  }
  return { qr: (op & 0x8000) === 0x8000, qd, an };
}

export function extractEndpoints(data: Uint8Array): EndpointRow[] {
  const agg = new Map<string, Omit<EndpointRow, "flows" | "hostnames">>();
  const names = new Map<string, Set<string>>();
  const flowsets = new Map<string, Set<string>>();
  const addName = (ip: string, n: string) => { let s = names.get(ip); if (!s) names.set(ip, s = new Set()); s.add(n); };

  for (const pkt of iterPackets(data)) {
    const ts = pkt.ts;
    try {
      const ip = decodeEthernet(pkt.data).ip;
      if (!ip || !ip.l4) continue;
      const l4 = ip.l4;
      const proto = l4.kind;
      const src = ip.src, dst = ip.dst;
      let out: boolean, remote: string, rport: number, lip: string, lport: number;
      if (isPrivate(src) && isPublic(dst)) { out = true; remote = dst; rport = l4.dport; lip = src; lport = l4.sport; }
      else if (isPublic(src) && isPrivate(dst)) { out = false; remote = src; rport = l4.sport; lip = dst; lport = l4.dport; }
      else continue;

      const key = `${remote}|${rport}|${proto}`;
      let e = agg.get(key);
      if (!e) {
        e = { remote_ip: remote, remote_port: rport, proto, packets: 0, bytes_out: 0, bytes_in: 0, first_ts: ts, last_ts: ts };
        agg.set(key, e);
      }
      e.packets++;
      if (out) e.bytes_out += ip.len; else e.bytes_in += ip.len;
      e.first_ts = Math.min(e.first_ts, ts);
      e.last_ts = Math.max(e.last_ts, ts);
      let fs = flowsets.get(key);
      if (!fs) flowsets.set(key, fs = new Set());
      fs.add(`${lip}:${lport}`);

      if (proto === "udp" && !out && rport === 53 && l4.data.length) {
        try {
          const d = parseDns(l4.data);
          if (d.qr && d.qd.length) {
            const qn = cleanName(d.qd[0]);
            for (const rr of d.an) {
              if (rr.type === 1 && qn) {
                if (rr.rdata.length !== 4) throw new Error("inet_ntoa: wrong length"); // socket.inet_ntoa
                addName(`${rr.rdata[0]}.${rr.rdata[1]}.${rr.rdata[2]}.${rr.rdata[3]}`, qn);
              }
            }
          }
        } catch { /* malformed DNS is ignored (names added before the error stay) */ }
      } else if (proto === "tcp" && out && l4.data.length) {
        const sni = parseSni(l4.data);
        if (sni) addName(remote, sni);
      }
    } catch {
      continue;
    }
  }

  const rows: EndpointRow[] = [];
  for (const [key, e] of agg) {
    rows.push({
      ...e,
      flows: flowsets.get(key)!.size,
      hostnames: [...(names.get(e.remote_ip) ?? [])].sort().slice(0, MAX_NAMES),
    });
  }
  rows.sort((a, b) => (b.bytes_out + b.bytes_in) - (a.bytes_out + a.bytes_in));
  return rows.slice(0, 2000);
}
