"""
Build-time patch: make the FastAPI server also serve the compiled React dashboard.

Critical: the SPA catch-all route MUST be registered LAST, after every API route,
because FastAPI matches routes in registration order and `/{full_path:path}`
matches everything (including /health, /status, /metrics ...).

This script APPENDS the static-serving block to the end of server.py so the
catch-all is always the final route. It also guards the catch-all to never
shadow real API paths.
"""
import pathlib

path = pathlib.Path("guardrail_framework/server.py")
src = path.read_text()

if "GUARDRAIL_STATIC_PATCH" in src:
    print("server.py already patched — skipping")
    raise SystemExit(0)

patch = '''

# ══════════════════════════════════════════════════════════════════════════════
# GUARDRAIL_STATIC_PATCH — serve the compiled React dashboard (registered LAST)
# ══════════════════════════════════════════════════════════════════════════════
import os as _os
from fastapi.staticfiles import StaticFiles as _StaticFiles
from fastapi.responses import HTMLResponse as _HTMLResponse, FileResponse as _FileResponse

_STATIC_DIR = _os.path.join(_os.path.dirname(__file__), "static")

if _os.path.isdir(_STATIC_DIR):
    # Mount the CRA build's /static (JS, CSS, media) under /static
    _assets_dir = _os.path.join(_STATIC_DIR, "static")
    if _os.path.isdir(_assets_dir):
        app.mount("/static", _StaticFiles(directory=_assets_dir), name="assets")

    # Collect the set of real API path prefixes so the SPA catch-all never
    # shadows them. Any first path segment registered as an API route is
    # treated as API and returns 404 (not index.html) when not matched.
    _API_PREFIXES = set()
    for _r in app.routes:
        _p = getattr(_r, "path", "")
        if _p and not _p.startswith("/static") and _p not in ("/", "/{full_path:path}"):
            _seg = _p.lstrip("/").split("/")[0].split("{")[0]
            if _seg:
                _API_PREFIXES.add(_seg)

    # Serve top-level static files (favicon, manifest, etc.)
    _REAL_STATIC_DIR = _os.path.realpath(_STATIC_DIR)

    @app.get("/{filename:path}", include_in_schema=False)
    def _serve_spa(filename: str = ""):
        # If the first segment is a known API prefix, this is a genuine 404,
        # not an SPA route — don't return HTML for it.
        first = filename.split("/")[0] if filename else ""
        if first in _API_PREFIXES:
            return _HTMLResponse("Not Found", status_code=404)

        # Serve a real static file if it exists (e.g. favicon.ico, manifest.json).
        # realpath() resolves any .. traversal before the containment check.
        candidate = _os.path.realpath(_os.path.join(_STATIC_DIR, filename))
        if (filename
                and candidate.startswith(_REAL_STATIC_DIR + _os.sep)
                and _os.path.isfile(candidate)):
            return _FileResponse(candidate)

        # Otherwise serve the SPA entrypoint (client-side routing)
        index = _os.path.join(_STATIC_DIR, "index.html")
        if _os.path.isfile(index):
            return _HTMLResponse(open(index).read())
        return _HTMLResponse("<h1>Dashboard build not found</h1>", status_code=404)

    @app.get("/", include_in_schema=False)
    def _serve_root():
        index = _os.path.join(_STATIC_DIR, "index.html")
        if _os.path.isfile(index):
            return _HTMLResponse(open(index).read())
        return _HTMLResponse("<h1>Guardrail API</h1><p>Dashboard build not found.</p>")
'''

path.write_text(src + patch)
print("server.py patched OK (static routes appended last)")
