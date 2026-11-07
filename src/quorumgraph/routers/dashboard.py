"""Operator dashboard: a static page that talks to the JSON API.

The page itself is public (it contains no data). Every data call it makes is
authenticated with the operator token the user enters, exactly like any other
API client. No server-side rendering, no build step, no external scripts.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Scripts/styles only from this origin (no inline, no CDN). connect-src allows
# localhost ports so the page can poll gateways on :8001/:8002 (they must also
# opt in via CORS).
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self' http://localhost:* http://127.0.0.1:*; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

router = APIRouter(include_in_schema=False)


@router.get("/dashboard")
def dashboard() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "dashboard.html",
        headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def mount_static(app) -> None:
    app.mount("/dashboard/static", StaticFiles(directory=STATIC_DIR), name="dashboard-static")
