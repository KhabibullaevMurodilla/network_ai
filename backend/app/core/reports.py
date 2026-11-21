"""Exportable PDF security-posture report (v6.3) -- a real PDF built with
reportlab from the same aggregates the dashboard itself reads, not a
screenshot or a wrapper around the dashboard UI. Meant for handing to a
compliance team or a boss who wants something they can save/forward/print
rather than a login to the dashboard."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from .db import get_db

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_COLOR = {
    "critical": colors.HexColor("#c4314b"),
    "high": colors.HexColor("#e8a33d"),
    "medium": colors.HexColor("#dccb4b"),
    "low": colors.HexColor("#8a8a8a"),
}


def _gather(tenant_id: str, days: int) -> dict:
    db = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    tenant = db.table("tenants").select("name, plan").eq("id", tenant_id).single().execute().data or {}

    # select+len rather than count="exact" -- keeps this testable against
    # the generic FakeDB harness (tests/fake_db.py), which models the
    # query-builder chain this codebase actually uses but not Supabase's
    # count= kwarg specifically.
    total_flows = len((
        db.table("telemetry_flows").select("id")
        .eq("tenant_id", tenant_id).gte("received_at", since).execute()
    ).data)

    anomalies = (
        db.table("anomaly_events").select("severity, src_ip, created_at")
        .eq("tenant_id", tenant_id).eq("detector", "ECOD").eq("is_anomaly", True)
        .gte("created_at", since).execute()
    ).data

    severity_counts = defaultdict(int)
    entity_counts: dict[str, dict] = defaultdict(lambda: {"event_count": 0, "max_severity": None})
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for a in anomalies:
        sev = a.get("severity")
        if sev:
            severity_counts[sev] += 1
        src = a.get("src_ip") or "unidentified"
        e = entity_counts[src]
        e["event_count"] += 1
        if rank.get(sev, -1) > rank.get(e["max_severity"], -1):
            e["max_severity"] = sev

    top_entities = sorted(entity_counts.items(), key=lambda kv: kv[1]["event_count"], reverse=True)[:10]

    incidents = (
        db.table("incidents").select("status, created_at")
        .eq("tenant_id", tenant_id).gte("created_at", since).execute()
    ).data
    incidents_opened = len(incidents)
    incidents_closed = sum(1 for i in incidents if i["status"] == "closed")

    return {
        "tenant_name": tenant.get("name", tenant_id),
        "plan": tenant.get("plan", "—"),
        "days": days,
        "total_flows": total_flows,
        "total_anomalies": len(anomalies),
        "severity_counts": severity_counts,
        "top_entities": top_entities,
        "incidents_opened": incidents_opened,
        "incidents_closed": incidents_closed,
    }


def generate_pdf_bytes(tenant_id: str, days: int = 30) -> bytes:
    """Builds and returns the actual PDF bytes for the given tenant's last
    `days` days. Pure function of (tenant_id, days, current DB state) --
    callable directly in a test without going through HTTP."""
    data = _gather(tenant_id, days)

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], textColor=colors.grey, fontSize=9)
    h2 = styles["Heading2"]
    body = styles["Normal"]

    elements = [
        Paragraph("Network AI — Security Posture Report", title_style),
        Spacer(1, 4),
        Paragraph(
            f"{data['tenant_name']} ({data['plan']} plan) &middot; last {data['days']} days &middot; "
            f"generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            meta_style,
        ),
        Spacer(1, 18),
        Paragraph("Summary", h2),
        Table(
            [
                ["Flows ingested", f"{data['total_flows']:,}"],
                ["Anomalies flagged", f"{data['total_anomalies']:,}"],
                ["Incidents opened", str(data["incidents_opened"])],
                ["Incidents closed", str(data["incidents_closed"])],
            ],
            colWidths=[2.5 * inch, 2 * inch],
            style=TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ]),
        ),
        Spacer(1, 18),
        Paragraph("Flagged events by severity", h2),
    ]

    sev_rows = [["Severity", "Count"]]
    for sev in SEVERITY_ORDER:
        sev_rows.append([sev.capitalize(), str(data["severity_counts"].get(sev, 0))])
    sev_table = Table(sev_rows, colWidths=[2.5 * inch, 2 * inch])
    sev_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ] + [
        ("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR[sev])
        for i, sev in enumerate(SEVERITY_ORDER, start=1)
    ]))
    elements += [sev_table, Spacer(1, 18), Paragraph("Top flagged entities", h2)]

    if data["top_entities"]:
        ent_rows = [["Source", "Events", "Worst severity"]]
        for src, e in data["top_entities"]:
            ent_rows.append([src, str(e["event_count"]), (e["max_severity"] or "—").capitalize()])
        ent_table = Table(ent_rows, colWidths=[2.3 * inch, 1.2 * inch, 1.5 * inch])
        ent_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(ent_table)
    else:
        elements.append(Paragraph("No flagged entities in this window.", body))

    elements += [
        Spacer(1, 24),
        Paragraph(
            "Generated directly from this tenant's own stored telemetry and detection output at "
            "request time -- not a static template. Scope: statistical/rule-based anomaly detection "
            "output only, not a substitute for a formal security audit or penetration test.",
            meta_style,
        ),
    ]

    doc.build(elements)
    return buf.getvalue()
