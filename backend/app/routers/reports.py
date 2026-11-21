"""Downloadable PDF security-posture reports (v6.3) -- the artifact a
tenant hands to a compliance team or a boss, generated on demand from
their own stored telemetry/detection output, not a static template."""
from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from ..core.auth import require_user
from ..core.audit import log_action
from ..core.limiter import limiter, user_key_func
from ..core.reports import generate_pdf_bytes

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/pdf")
@limiter.limit("10/minute", key_func=user_key_func)
async def download_pdf_report(request: Request, days: int = Query(30, le=365), user=Depends(require_user)):
    pdf_bytes = generate_pdf_bytes(user["tenant_id"], days)
    log_action(user["tenant_id"], actor=user["user_id"], action="report.generated", detail={"days": days})
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=network-ai-report-{days}d.pdf"},
    )
