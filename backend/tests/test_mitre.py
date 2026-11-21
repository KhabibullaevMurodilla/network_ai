"""Unit tests for core.mitre's best-effort ATT&CK mapping. See the
module's own docstring for the honesty caveat this mapping carries
(training-knowledge-derived, not live-fetched, not independently
re-verified) -- these tests pin the mapping's *behavior* (what gets
tagged, what deliberately doesn't), not the correctness of MITRE's own
technique IDs, which this sandbox cannot verify against a live source."""
from app.core.mitre import mitre_for_anomaly_event, mitre_for_ot_event, ENTERPRISE_MAPPING, ICS_MAPPING


def test_entity_burst_maps_to_a_technique():
    m = mitre_for_anomaly_event("entity_burst")
    assert m is not None
    assert m["technique_id"] == "T1595"
    assert m["framework"] == "ATT&CK Enterprise"


def test_entity_baseline_drift_maps_to_a_technique():
    m = mitre_for_anomaly_event("entity_baseline_drift")
    assert m is not None
    assert m["technique_id"] == "T1071"


def test_ensemble_consensus_deliberately_unmapped():
    """Not a gap -- see the module docstring: statistical multi-detector
    agreement has no specific-enough technique signature to defensibly tag."""
    assert mitre_for_anomaly_event("ensemble_consensus") is None


def test_none_reason_returns_none():
    assert mitre_for_anomaly_event(None) is None


def test_all_four_ot_rule_reasons_map_to_ics_techniques():
    for reason in ("new_function_code", "unexpected_write_address", "exception_flood", "unit_id_scan"):
        m = mitre_for_ot_event(reason)
        assert m is not None, f"{reason} should have an ICS mapping"
        assert m["framework"] == "ATT&CK for ICS"
        assert m["technique_id"].startswith("T0")


def test_unknown_ot_reason_returns_none():
    assert mitre_for_ot_event("something_new_and_unmapped") is None


def test_every_mapping_entry_has_a_confidence_and_note():
    for mapping in (ENTERPRISE_MAPPING, ICS_MAPPING):
        for reason, entry in mapping.items():
            assert entry.get("confidence"), f"{reason} missing confidence field"
            assert entry.get("note"), f"{reason} missing explanatory note"
