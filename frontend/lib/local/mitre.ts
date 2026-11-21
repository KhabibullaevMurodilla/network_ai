/** Same best-effort ATT&CK mapping as backend/app/core/mitre.py (flow-level
 *  reasons only; the OT/ICS mapping needs the Modbus rules, not in local mode).
 *  Indicative, not a packet-signature match; verify IDs before any compliance claim. */
export interface Mitre { framework: string; tactic: string; technique_id: string; technique: string; confidence: string; note: string }
const M: Record<string, Mitre> = {
  entity_burst: {
    framework: "ATT&CK Enterprise", tactic: "Reconnaissance", technique_id: "T1595", technique: "Active Scanning", confidence: "indicative",
    note: "A burst of flagged traffic from one host in a short window commonly corresponds to scanning/enumeration behavior; could also indicate a DoS source or data exfiltration. Not a packet-signature match -- a volumetric pattern this rule recognizes, not a confirmed technique.",
  },
  entity_baseline_drift: {
    framework: "ATT&CK Enterprise", tactic: "Command and Control", technique_id: "T1071", technique: "Application Layer Protocol", confidence: "indicative",
    note: "Sustained deviation from a host's own established traffic baseline is a common signature of long-lived C2 beaconing, but is not specific to it -- a legitimate workload change produces the same signal.",
  },
};
export const mitreForReason = (reason: string | null | undefined): Mitre | null => (reason ? M[reason] ?? null : null);

const ICS: Record<string, Mitre> = {
  new_function_code: { framework: "ATT&CK for ICS", tactic: "Impair Process Control", technique_id: "T0855", technique: "Unauthorized Command Message", confidence: "indicative",
    note: "A Modbus function code never previously seen from this device is the rule-level pattern for an unauthorized command type being issued." },
  unexpected_write_address: { framework: "ATT&CK for ICS", tactic: "Impair Process Control", technique_id: "T0836", technique: "Modify Parameter", confidence: "indicative",
    note: "A write outside this device's previously observed address range is the rule-level pattern for unauthorized parameter tampering." },
  exception_flood: { framework: "ATT&CK for ICS", tactic: "Inhibit Response Function", technique_id: "T0814", technique: "Denial of Service", confidence: "indicative",
    note: "A burst of Modbus exception responses is the rule-level pattern for a device being driven into a fault/DoS-like state." },
  unit_id_scan: { framework: "ATT&CK for ICS", tactic: "Discovery", technique_id: "T0846", technique: "Remote System Discovery", confidence: "indicative",
    note: "One source querying many Modbus unit IDs in sequence is the rule-level pattern for device/address-space enumeration." },
};
export const mitreForOtReason = (reason: string | null | undefined): Mitre | null => (reason ? ICS[reason] ?? null : null);
