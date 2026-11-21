"""Best-effort MITRE ATT&CK (Enterprise) / ATT&CK for ICS technique mapping
for this product's own detection reasons -- surfaced on flagged events so
an analyst or auditor gets a recognized framework reference, not just this
product's internal reason string.

Stated plainly: these technique IDs come from this session's training-data
knowledge of the ATT&CK framework, not a live fetch from attack.mitre.org
(this sandbox has no network access to verify them against the current
matrix). Before using this mapping in a customer-facing compliance claim,
verify each ID against the live MITRE ATT&CK site -- technique IDs are
occasionally deprecated, merged, or renumbered between framework
revisions, and this mapping has not been independently re-verified against
a live copy of either matrix.

Deliberately conservative: a detection reason only gets a mapping when
there is a defensible, specific link to a named technique.
'ensemble_consensus' (multiple independent ML models agreeing a flow is
statistically anomalous) has no technique-specific enough signature and is
left unmapped rather than force-fit to one -- tagging it would overclaim
what a volumetric anomaly detector can actually attribute. Every mapping
below also carries a 'confidence' field for the same reason: none of these
are a packet-level signature match to a known technique, they're a
statistical/rule-based pattern that commonly correlates with one.
"""

# Enterprise ATT&CK -- flow-level ML detector escalation reasons.
ENTERPRISE_MAPPING: dict[str, dict] = {
    "entity_burst": {
        "framework": "ATT&CK Enterprise",
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
        "confidence": "indicative",
        "note": (
            "A burst of flagged traffic from one host in a short window commonly "
            "corresponds to scanning/enumeration behavior; could also indicate a "
            "DoS source or data exfiltration. Not a packet-signature match -- a "
            "volumetric pattern this rule recognizes, not a confirmed technique."
        ),
    },
    "entity_baseline_drift": {
        "framework": "ATT&CK Enterprise",
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique": "Application Layer Protocol",
        "confidence": "indicative",
        "note": (
            "Sustained deviation from a host's own established traffic baseline is "
            "a common signature of long-lived C2 beaconing, but is not specific to "
            "it -- a legitimate workload change produces the same signal."
        ),
    },
}

# ATT&CK for ICS -- Modbus/TCP rule-engine reasons (ml/ot_rules.py).
ICS_MAPPING: dict[str, dict] = {
    "new_function_code": {
        "framework": "ATT&CK for ICS",
        "tactic": "Impair Process Control",
        "technique_id": "T0855",
        "technique": "Unauthorized Command Message",
        "confidence": "indicative",
        "note": "A Modbus function code never previously seen from this device is the rule-level pattern for an unauthorized command type being issued.",
    },
    "unexpected_write_address": {
        "framework": "ATT&CK for ICS",
        "tactic": "Impair Process Control",
        "technique_id": "T0836",
        "technique": "Modify Parameter",
        "confidence": "indicative",
        "note": "A write outside this device's previously observed address range is the rule-level pattern for unauthorized parameter tampering.",
    },
    "exception_flood": {
        "framework": "ATT&CK for ICS",
        "tactic": "Inhibit Response Function",
        "technique_id": "T0814",
        "technique": "Denial of Service",
        "confidence": "indicative",
        "note": "A burst of Modbus exception responses is the rule-level pattern for a device being driven into a fault/DoS-like state.",
    },
    "unit_id_scan": {
        "framework": "ATT&CK for ICS",
        "tactic": "Discovery",
        "technique_id": "T0846",
        "technique": "Remote System Discovery",
        "confidence": "indicative",
        "note": "One source querying many Modbus unit IDs in sequence is the rule-level pattern for device/address-space enumeration.",
    },
}


def mitre_for_anomaly_event(escalation_reason: str | None) -> dict | None:
    """ML-detector flow anomalies (anomaly_events.escalation_reason)."""
    if not escalation_reason:
        return None
    return ENTERPRISE_MAPPING.get(escalation_reason)


def mitre_for_ot_event(reason: str | None) -> dict | None:
    """Deterministic OT rule-engine events (ot_protocol_events.reason)."""
    if not reason:
        return None
    return ICS_MAPPING.get(reason)
