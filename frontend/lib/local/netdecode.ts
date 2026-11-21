/** Shared low-level decoding for discovery.ts / endpoints.ts. It mirrors what
 *  the Python ingestion modules get from `dpkt` (Ethernet II + 802.1Q/QinQ,
 *  IPv4, TCP, UDP, ARP) and from the stdlib `ipaddress` module, including the
 *  places where dpkt silently gives up (so the browser and the backend skip
 *  exactly the same frames).
 *
 *  Like the Python code it treats EVERY frame as Ethernet regardless of the
 *  capture's link type, and it does not decode MPLS, Cisco ISL or Novell raw
 *  frames (dpkt does; those frames are skipped here). */
import { classicPackets, pcapngPackets } from "./pcap";

export interface RawPkt { ts: number; data: Uint8Array }

const CLASSIC_MAGICS = [[0xd4, 0xc3, 0xb2, 0xa1], [0xa1, 0xb2, 0xc3, 0xd4], [0x4d, 0x3c, 0xb2, 0xa1], [0xa1, 0xb2, 0x3c, 0x4d]];

/** backend/app/ingestion/pcap.py::_looks_like_classic_pcap */
function looksClassic(d: Uint8Array): boolean {
  if (d.length < 4) return true;
  return CLASSIC_MAGICS.some(m => m.every((b, i) => d[i] === b));
}

/** Packets of a classic pcap or pcapng. Never throws: a bad/short header yields
 *  nothing, damage mid-file stops the iteration (Python: empty list / break). */
export function* iterPackets(data: Uint8Array): Generator<RawPkt> {
  try {
    if (looksClassic(data)) {
      if (data.length < 24) return;
      for (const p of classicPackets(data)) yield { ts: p.ts, data: p.data };
    } else {
      // dpkt.pcapng.Reader needs a Section Header Block first
      if (data.length < 12 || data[0] !== 0x0a || data[1] !== 0x0d || data[2] !== 0x0d || data[3] !== 0x0a) return;
      for (const p of pcapngPackets(data)) yield { ts: p.ts, data: p.data };
    }
  } catch {
    return;
  }
}

export function macStr(raw: Uint8Array): string {
  let s = "";
  for (let i = 0; i < raw.length; i++) s += (i ? ":" : "") + raw[i].toString(16).padStart(2, "0");
  return s;
}

export function ipStr(b: Uint8Array, o: number): string {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}

const lenient = new TextDecoder("utf-8", { ignoreBOM: true });
const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
/** bytes.decode("utf-8", "replace") */
export function decodeReplace(b: Uint8Array): string { return lenient.decode(b); }
/** bytes.decode("utf-8") -- throws on invalid input like Python */
export function decodeStrict(b: Uint8Array): string { return strict.decode(b); }

export const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];

// ---- ipaddress semantics (Python 3.13) ------------------------------------
function ipNum(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    n = n * 256 + Number(x);
  }
  return n;
}
const net = (a: string, bits: number): [number, number] => {
  const size = 2 ** (32 - bits);
  return [ipNum(a)!, size];
};
const inNet = (n: number, [base, size]: [number, number]) => n >= base && n < base + size;
const PRIVATE = [
  net("0.0.0.0", 8), net("10.0.0.0", 8), net("127.0.0.0", 8), net("169.254.0.0", 16), net("172.16.0.0", 12),
  net("192.0.0.0", 24), net("192.0.0.170", 31), net("192.0.2.0", 24), net("192.168.0.0", 16), net("198.18.0.0", 15),
  net("198.51.100.0", 24), net("203.0.113.0", 24), net("240.0.0.0", 4), net("255.255.255.255", 32),
];
const PRIVATE_EXCEPT = [net("192.0.0.9", 32), net("192.0.0.10", 32)];
const SHARED = net("100.64.0.0", 10);
const MULTICAST = net("224.0.0.0", 4);
const LOOPBACK = net("127.0.0.0", 8);

function pyIsPrivate(n: number): boolean { return PRIVATE.some(x => inNet(n, x)) && !PRIVATE_EXCEPT.some(x => inNet(n, x)); }
function pyIsGlobal(n: number): boolean { return !inNet(n, SHARED) && !pyIsPrivate(n); }

/** `a.is_private and not (multicast or unspecified or loopback)` */
export function isPrivate(ip: string): boolean {
  const n = ipNum(ip);
  if (n === null) return false;
  return pyIsPrivate(n) && !(inNet(n, MULTICAST) || n === 0 || inNet(n, LOOPBACK));
}
/** `a.is_global and not a.is_multicast` */
export function isPublic(ip: string): boolean {
  const n = ipNum(ip);
  if (n === null) return false;
  return pyIsGlobal(n) && !inNet(n, MULTICAST);
}

// ---- dpkt-equivalent frame decoding ---------------------------------------
export interface Tcp { kind: "tcp"; sport: number; dport: number; flags: number; data: Uint8Array }
export interface Udp { kind: "udp"; sport: number; dport: number; data: Uint8Array }
export interface Ip4 { src: string; dst: string; ttl: number; len: number; l4: Tcp | Udp | null }
export interface Decoded { arp: { sha: string; spa: string } | null; ip: Ip4 | null }

export const TH_SYN = 0x02, TH_ACK = 0x10;
const QINQ = new Set([0x8100, 0x88a8, 0x9100, 0x9200]);

/** dpkt.ethernet.Ethernet(buf): ARP / IPv4 payload or nothing. Everything dpkt
 *  would raise on or leave as raw bytes is returned as {arp:null, ip:null}. */
export function decodeEthernet(buf: Uint8Array): Decoded {
  const none: Decoded = { arp: null, ip: null };
  if (buf.length < 14) return none;
  const type = u16(buf, 12);
  if (type <= 1500) return none; // 802.3/LLC (or ISL/Novell raw): never ARP/IPv4 here
  let next = type;
  let o = 14;
  if (QINQ.has(next)) {
    for (let k = 0; k < 2; k++) {
      if (buf.length < o + 4) return none; // dpkt raises
      next = u16(buf, o + 2);
      o += 4;
      if (next !== 0x8100) break;
    }
    if (next === 0) next = type;
  }
  const body = buf.subarray(o);
  if (next === 0x0806) {
    if (body.length < 28) return none;
    return { arp: { sha: macStr(body.subarray(8, 14)), spa: ipStr(body, 14) }, ip: null };
  }
  if (next === 0x0800) return { arp: null, ip: decodeIp4(body) };
  return none;
}

function decodeIp4(b: Uint8Array): Ip4 | null {
  if (b.length < 20) return null;
  const ihl = (b[0] & 0x0f) << 2;
  if (ihl < 20) return null;
  const len = u16(b, 2);
  const ip: Ip4 = { src: ipStr(b, 12), dst: ipStr(b, 16), ttl: b[8], len, l4: null };
  const data = len ? b.subarray(ihl, len) : b.subarray(ihl);
  if ((u16(b, 6) & 0x1fff) !== 0) return ip; // non-first fragment: dpkt keeps raw bytes
  const proto = b[9];
  if (proto === 6) {
    if (data.length < 20) return ip;
    const hl = (data[12] >> 4) << 2;
    if (hl < 20) return ip;
    ip.l4 = { kind: "tcp", sport: u16(data, 0), dport: u16(data, 2), flags: u16(data, 12) & 0x1ff, data: data.subarray(hl) };
  } else if (proto === 17) {
    if (data.length < 8) return ip;
    ip.l4 = { kind: "udp", sport: u16(data, 0), dport: u16(data, 2), data: data.subarray(8) };
  }
  return ip;
}
