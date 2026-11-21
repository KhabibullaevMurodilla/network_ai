/** Parses a capture file (classic pcap or pcapng) into flows, entirely in the
 *  browser. Mirrors backend/app/ingestion/pcap.py: bidirectional 5-tuple flows,
 *  60 s inactivity timeout, close on RST or on FIN from both sides. IPv4 only
 *  (like the Python version); non-IP frames are skipped. */
import type { Flow } from "./types";

const FLOW_TIMEOUT = 60;
const PROTO: Record<number, string> = { 6: "TCP", 17: "UDP", 1: "ICMP" };

export interface Pkt { ts: number; data: Uint8Array; link: number }

export function* classicPackets(buf: Uint8Array): Generator<Pkt> {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const m = dv.getUint32(0, false);
  let le: boolean, nano: boolean;
  if (m === 0xa1b2c3d4) { le = false; nano = false; }
  else if (m === 0xd4c3b2a1) { le = true; nano = false; }
  else if (m === 0xa1b23c4d) { le = false; nano = true; }
  else if (m === 0x4d3cb2a1) { le = true; nano = true; }
  else throw new Error("Not a pcap file");
  const link = dv.getUint32(20, le);
  let off = 24;
  while (off + 16 <= buf.length) {
    const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le);
    const caplen = dv.getUint32(off + 8, le);
    off += 16;
    const ts = sec + frac / (nano ? 1e9 : 1e6);
    // truncated final record: like dpkt (f.read(caplen)), yield the bytes that are there, then stop
    if (off + caplen > buf.length) { yield { ts, data: buf.subarray(off), link }; return; }
    yield { ts, data: buf.subarray(off, off + caplen), link };
    off += caplen;
  }
}

export function* pcapngPackets(buf: Uint8Array): Generator<Pkt> {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let le = true;
  const ifaces: { link: number; div: number; off: number }[] = []; // ts = off + ticks / div (as dpkt)
  let off = 0;
  while (off + 12 <= buf.length) {
    const typeBE = dv.getUint32(off, false);
    if (typeBE === 0x0a0d0d0a) { // section header: byte-order magic decides endianness
      le = dv.getUint32(off + 8, true) === 0x1a2b3c4d;
      ifaces.length = 0;
    }
    const type = dv.getUint32(off, le);
    const len = dv.getUint32(off + 4, le);
    if (len < 12 || off + len > buf.length) return;
    if (type === 1) { // interface description
      const link = dv.getUint16(off + 8, le);
      let div = 1e6, tsoff = 0;
      let o = off + 16;
      while (o + 4 <= off + len - 4) {
        const code = dv.getUint16(o, le), olen = dv.getUint16(o + 2, le);
        if (code === 0) break;
        if (code === 9 && olen >= 1) {
          const v = dv.getUint8(o + 4);
          div = v & 0x80 ? Math.pow(2, v & 0x7f) : Math.pow(10, v);
        } else if (code === 14 && olen >= 8) {
          tsoff = Number(dv.getBigInt64(o + 4, le));
        }
        o += 4 + ((olen + 3) & ~3);
      }
      ifaces.push({ link, div, off: tsoff });
    } else if (type === 6 && ifaces.length) { // enhanced packet
      const ifc = ifaces[dv.getUint32(off + 8, le)] ?? ifaces[0];
      const hi = dv.getUint32(off + 12, le), lo = dv.getUint32(off + 16, le);
      const caplen = dv.getUint32(off + 20, le);
      if (off + 28 + caplen <= off + len) {
        yield { ts: ifc.off + (hi * 4294967296 + lo) / ifc.div, data: buf.subarray(off + 28, off + 28 + caplen), link: ifc.link };
      }
    } else if (type === 3 && ifaces.length) { // simple packet (no timestamp)
      const caplen = Math.min(dv.getUint32(off + 8, le), len - 16);
      yield { ts: 0, data: buf.subarray(off + 12, off + 12 + caplen), link: ifaces[0].link };
    }
    off += len;
  }
}

/** Returns the IPv4 packet inside a link-layer frame, or null. */
export function ipv4Of(p: Pkt): Uint8Array | null {
  const d = p.data;
  let o = 0;
  if (p.link === 1) { // Ethernet (+ optional VLAN tags)
    if (d.length < 14) return null;
    let et = (d[12] << 8) | d[13];
    o = 14;
    while ((et === 0x8100 || et === 0x88a8) && d.length >= o + 4) { et = (d[o + 2] << 8) | d[o + 3]; o += 4; }
    if (et !== 0x0800) return null;
  } else if (p.link === 113) { // Linux cooked
    if (d.length < 16 || ((d[14] << 8) | d[15]) !== 0x0800) return null;
    o = 16;
  } else if (p.link === 0) { // BSD loopback (Windows "Npcap Loopback Adapter")
    if (d.length < 4 || (d[0] !== 2 && d[3] !== 2)) return null;
    o = 4;
  } else if (p.link === 101 || p.link === 228) { // raw IP
    o = 0;
  } else return null;
  // dpkt trusts the ethertype and never checks the IP version nibble; only the non-Ethernet link types need it
  if (d.length < o + 20 || (p.link !== 1 && d[o] >> 4 !== 4)) return null;
  return d.subarray(o);
}

interface Acc {
  first: number; last: number; src: string; dst: string; sport: number; proto: string;
  pkts: number; srcBytes: number; dstBytes: number; ttl: number; fins: Set<boolean>; rst: boolean;
}

export function parseCapture(data: Uint8Array): Flow[] {
  if (data.length < 24) throw new Error("File is too small to be a capture.");
  const isNg = data[0] === 0x0a && data[1] === 0x0d && data[2] === 0x0d && data[3] === 0x0a;
  const packets = isNg ? pcapngPackets(data) : classicPackets(data);
  const active = new Map<string, Acc>();
  const done: Flow[] = [];
  let sawFrames = 0;

  const close = (key: string) => {
    const a = active.get(key);
    active.delete(key);
    if (!a || a.pkts === 0) return;
    const dur = Math.max(a.last - a.first, 0);
    const tot = a.srcBytes + a.dstBytes;
    const rate = dur > 0 ? a.pkts / dur : a.pkts;
    const load = dur > 0 ? (tot * 8) / dur : tot * 8;
    done.push({
      dur: round(dur, 6), proto: a.proto, tot_pkts: a.pkts, src_bytes: a.srcBytes, dst_bytes: a.dstBytes,
      rate: round(rate, 4), load: round(load, 4), s_ttl: a.ttl, src_ip: a.src, dst_ip: a.dst,
      ...(a.first > 0 ? { ts: a.first } : {}),
    });
  };

  for (const p of packets) {
    sawFrames++;
    const ip = ipv4Of(p);
    if (!ip) continue;
    const ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || ip.length < ihl) continue;
    const total = (ip[2] << 8) | ip[3];
    const length = Math.min(total || ip.length, ip.length);
    const ttl = ip[8], pn = ip[9];
    const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`, dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
    const proto = PROTO[pn] ?? "OTHER";
    let sp = 0, dp = 0, fin = false, rst = false;
    if ((pn === 6 || pn === 17) && ip.length >= ihl + 4) {
      sp = (ip[ihl] << 8) | ip[ihl + 1]; dp = (ip[ihl + 2] << 8) | ip[ihl + 3];
      if (pn === 6 && ip.length >= ihl + 14) { const fl = ip[ihl + 13]; fin = !!(fl & 0x01); rst = !!(fl & 0x04); }
    }
    const a = src < dst || (src === dst && sp <= dp) ? `${src}:${sp}` : `${dst}:${dp}`;
    const b = a === `${src}:${sp}` ? `${dst}:${dp}` : `${src}:${sp}`;
    const key = `${a}|${b}|${proto}`;
    let acc = active.get(key);
    if (acc && p.ts - acc.last > FLOW_TIMEOUT) { close(key); acc = undefined; }
    if (!acc) {
      acc = { first: p.ts, last: p.ts, src, dst, sport: sp, proto, pkts: 0, srcBytes: 0, dstBytes: 0, ttl, fins: new Set(), rst: false };
      active.set(key, acc);
    }
    acc.last = p.ts; acc.pkts++;
    const fwd = src === acc.src && sp === acc.sport;   // IP and port: loopback has one IP on both ends
    if (fwd) acc.srcBytes += length; else acc.dstBytes += length;
    if (fin) acc.fins.add(fwd);
    if (rst) acc.rst = true;
    if (acc.rst || acc.fins.size >= 2) close(key);
  }
  for (const key of [...active.keys()]) close(key);
  if (sawFrames === 0) throw new Error("No packets found - is this a valid pcap/pcapng file?");
  return done;
}

function round(v: number, n: number): number { const m = Math.pow(10, n); return Math.round(v * m) / m; }
