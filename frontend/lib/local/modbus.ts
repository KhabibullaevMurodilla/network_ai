/** Modbus/TCP message parser for the browser. Mirrors
 *  backend/app/ingestion/modbus.py (parse_modbus_pcap_bytes): one record per
 *  Modbus ADU, one ADU per TCP segment (no stream reassembly), request vs
 *  response decided by port direction. Same field names and values. */
import { classicPackets, pcapngPackets, ipv4Of } from "./pcap";
import type { Pkt } from "./pcap";

export const DEFAULT_MODBUS_PORT = 502;

export const FUNCTION_NAMES: Record<number, string> = {
  1: "ReadCoils", 2: "ReadDiscreteInputs", 3: "ReadHoldingRegisters",
  4: "ReadInputRegisters", 5: "WriteSingleCoil", 6: "WriteSingleRegister",
  7: "ReadExceptionStatus", 8: "Diagnostics", 11: "GetCommEventCounter",
  15: "WriteMultipleCoils", 16: "WriteMultipleRegisters",
  17: "ReportSlaveId", 20: "ReadFileRecord", 21: "WriteFileRecord",
  22: "MaskWriteRegister", 23: "ReadWriteMultipleRegisters",
  24: "ReadFIFOQueue", 43: "EncapsulatedInterfaceTransport",
};

export interface ModbusMessage {
  ts: number;
  src_ip: string;
  dst_ip: string;
  unit_id: number;
  function_code: number;
  function_name: string;
  is_request: boolean;
  is_exception: boolean;
  exception_code: number | null;
  address: number | null;
  quantity: number | null;
}

/** Packet iterator over classic pcap or pcapng bytes (throws on anything else,
 *  like the Python parser's ValueError). */
export function* iterPackets(data: Uint8Array): Generator<Pkt> {
  if (data.length < 24) throw new Error("Not a recognizable pcap/pcapng file: too small");
  const isNg = data[0] === 0x0a && data[1] === 0x0d && data[2] === 0x0d && data[3] === 0x0a;
  yield* isNg ? pcapngPackets(data) : classicPackets(data);
}

const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];

function decodePdu(pdu: Uint8Array, isRequest: boolean):
  { fc: number; name: string; exc: boolean; excCode: number | null; address: number | null; quantity: number | null } {
  if (pdu.length === 0) return { fc: 0, name: "Empty", exc: false, excCode: null, address: null, quantity: null };
  const raw = pdu[0];
  const exc = !!(raw & 0x80);
  const fc = raw & 0x7f;
  const name = FUNCTION_NAMES[fc] ?? `Unknown(${fc})`;
  if (exc) return { fc, name, exc: true, excCode: pdu.length > 1 ? pdu[1] : null, address: null, quantity: null };
  let address: number | null = null, quantity: number | null = null;
  if (pdu.length >= 5) {
    if (isRequest && fc >= 1 && fc <= 4) { address = u16(pdu, 1); quantity = u16(pdu, 3); }
    else if (fc === 5 || fc === 6) { address = u16(pdu, 1); quantity = 1; }     // request and echoed response
    else if (fc === 15 || fc === 16) { address = u16(pdu, 1); quantity = u16(pdu, 3); } // request and response
    // read responses (fc 1-4, not request) carry a byte count only
  }
  return { fc, name, exc: false, excCode: null, address, quantity };
}

export function parseModbus(data: Uint8Array, port = DEFAULT_MODBUS_PORT): ModbusMessage[] {
  const out: ModbusMessage[] = [];
  for (const p of iterPackets(data)) {
    const ip = ipv4Of(p);
    if (!ip) continue;
    const ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20) continue;                       // dpkt: invalid header length
    if (ip[9] !== 6) continue;                    // TCP only
    if ((((ip[6] & 0x1f) << 8) | ip[7]) !== 0) continue; // fragment (offset != 0): dpkt leaves it raw
    const total = u16(ip, 2);
    const end = total ? Math.min(total, ip.length) : ip.length; // dpkt: buf[hl:len]; len 0 -> to end
    if (end < ihl + 20) continue;                 // TCP header needs 20 bytes
    const tcp = ip.subarray(ihl, end);
    const thl = (tcp[12] >> 4) << 2;
    if (thl < 20) continue;                       // dpkt: invalid TCP header length
    const sport = u16(tcp, 0), dport = u16(tcp, 2);
    if (sport !== port && dport !== port) continue;
    const payload = tcp.subarray(Math.min(thl, tcp.length));
    if (payload.length < 8) continue;
    const length = u16(payload, 4);
    if (u16(payload, 2) !== 0) continue;          // protocol id must be 0
    const unitId = payload[6];
    const pdu = payload.subarray(7, 7 + Math.max(length - 1, 0));
    const isRequest = dport === port;
    const d = decodePdu(pdu, isRequest);
    if (d.fc === 0) continue;
    out.push({
      ts: p.ts,
      src_ip: `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`,
      dst_ip: `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`,
      unit_id: unitId, function_code: d.fc, function_name: d.name,
      is_request: isRequest, is_exception: d.exc, exception_code: d.excCode,
      address: d.address, quantity: d.quantity,
    });
  }
  return out;
}
