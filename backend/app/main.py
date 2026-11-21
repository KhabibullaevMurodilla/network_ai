import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from .core.config import settings
from .core.limiter import limiter
from .core.logging_config import configure_logging
from .routers import ingest, dashboard, billing, tenants, privacy, webhooks, incidents, response_actions, health, reports, demo, team

configure_logging()
logger = logging.getLogger("network_ai")

app = FastAPI(
    title="Network AI — Anomaly Detection API",
    description="Multi-tenant AI anomaly detection for private 4G/5G and OT networks.",
    version="0.6.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Defense in depth: FastAPI's own default already keeps a raw
    traceback out of the HTTP response when debug mode is off (it is,
    here -- no debug=True anywhere in this app), but that default also
    means an unexpected bug just returns a bare, unlogged 500. This makes
    the failure mode explicit and operable: full detail goes to the
    structured logs (where an operator can actually act on it), the caller
    gets a generic message with no internals -- no stack trace, no
    exception class name, no file paths -- regardless of what the
    exception actually was."""
    logger.error(
        "unhandled_exception",
        extra={"path": request.url.path, "method": request.method},
        exc_info=exc,
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# No wildcard: ALLOWED_ORIGINS must be set to the exact frontend origin(s)
# in production (see .env.example). An empty list fails closed -- every
# browser-origin request is rejected -- rather than silently allowing any
# site to call this API with a logged-in user's credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Real finding from adversarial review: this API set no security
    headers at all beyond CORS. This is a pure JSON API (never serves
    HTML it generated from user input), so the actual exploitable-XSS
    surface these headers defend against is already small -- but an
    enterprise security review checks for these on every response
    regardless, and their absence is exactly the kind of "fails the
    checklist even though nothing is directly exploitable today" finding
    that costs credibility in a real audit. Cheap to add, no downside."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # This API returns tenant-scoped data keyed off a bearer token, not
        # cookies -- nothing here should ever be cached by a shared proxy
        # or left in browser disk cache.
        response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.include_router(ingest.router)
app.include_router(dashboard.router)
app.include_router(billing.router)
app.include_router(tenants.router)
app.include_router(privacy.router)
app.include_router(webhooks.router)
app.include_router(incidents.router)
app.include_router(response_actions.router)
app.include_router(health.router)
app.include_router(reports.router)
app.include_router(demo.router)
app.include_router(team.router)
