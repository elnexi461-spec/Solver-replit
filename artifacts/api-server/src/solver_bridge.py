"""Private IPC bridge to the pinned upstream solver modules.

The repository's checked-in server.py is line-number-prefixed and truncated inside its
last docstring. This bridge extracts its intact Pydantic models, URL guard, and original
solver dispatcher; solver implementations and browser logic remain upstream code.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any


def _load_upstream(root: Path) -> dict[str, Any]:
    sys.path.insert(0, str(root))
    logging.disable(logging.CRITICAL)
    source_path = root / "server.py"
    source = source_path.read_text(encoding="utf-8")
    normalized = "\n".join(re.sub(r"^\s*\d+\|", "", line) for line in source.splitlines())

    health_route = normalized.find('\n@app.get("/health"')
    extract_function = normalized.find("\ndef _extract(")
    solve_route = normalized.find('\n@app.post("/solve"')
    if min(health_route, extract_function, solve_route) < 0:
        raise RuntimeError("upstream_dispatch_missing")

    namespace: dict[str, Any] = {"__name__": "captcha_solver_runtime"}
    compile(normalized[:health_route], str(source_path), "exec")
    exec(compile(normalized[:health_route], str(source_path), "exec"), namespace)
    dispatcher_source = normalized[extract_function:solve_route]
    exec(compile(dispatcher_source, str(source_path), "exec"), namespace)
    return namespace


async def _solve(root: Path, payload: Any) -> dict[str, Any]:
    try:
        namespace = _load_upstream(root)
        request = namespace["SolveRequest"].model_validate(payload)
        supported = namespace["SUPPORTED"]
        if request.type not in supported:
            return {"http_status": 400, "detail": "Unsupported solver type."}

        required = {
            "turnstile": ("sitekey", "url"),
            "recaptcha": ("sitekey", "url"),
            "hcaptcha": ("sitekey", "url"),
            "cloudflare": ("url",),
            "awswaf": ("url",),
            "datadome": ("url",),
            "akamai": ("url",),
            "aliyun": ("scene_id", "prefix"),
        }.get(request.type, ())
        if any(not getattr(request, field) for field in required):
            return {"http_status": 400, "detail": "A required field is missing for this solver type."}

        namespace["_validate_urls"](request)
        try:
            result = await asyncio.wait_for(
                namespace["_dispatch"](request), timeout=request.timeout_s or 60
            )
        except asyncio.TimeoutError:
            return {"http_status": 408, "detail": "Solver deadline exceeded."}
        result = {"type": request.type, **result}
        result["solved"] = namespace["_is_solved"](result)
        return {"http_status": 200, "result": result}
    except Exception as exc:
        # Translate validation/SSRF errors without forwarding user data or tracebacks.
        try:
            from fastapi import HTTPException
            from pydantic import ValidationError
        except ImportError:
            return {"http_status": 502, "detail": "Upstream solver unavailable."}
        if isinstance(exc, HTTPException):
            return {
                "http_status": exc.status_code,
                "detail": str(exc.detail) if isinstance(exc.detail, str) else "Invalid request.",
            }
        if isinstance(exc, ValidationError):
            return {"http_status": 422, "detail": "Request does not match the upstream solver schema."}
        return {"http_status": 502, "detail": "Upstream solver failed."}


async def _probe(root: Path) -> dict[str, Any]:
    try:
        _load_upstream(root)
        import cloakbrowser

        browser = await cloakbrowser.launch_async(headless=True, humanize=False)
        await browser.close()
        return {"ok": True, "browser": "CloakBrowser launched and closed successfully."}
    except Exception:
        return {"ok": False, "browser": "CloakBrowser could not launch.", "blocker": "browser_launch_failed"}


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"ok": False, "blocker": "invalid_bridge_arguments"}))
        return 2
    mode, root_arg = sys.argv[1:]
    root = Path(root_arg).resolve()
    if not root.joinpath("server.py").is_file():
        print(json.dumps({"ok": False, "blocker": "upstream_source_missing"}))
        return 2
    try:
        if mode == "--health":
            result = asyncio.run(_probe(root))
        elif mode == "--solve":
            payload = json.load(sys.stdin)
            result = asyncio.run(_solve(root, payload))
        else:
            result = {"ok": False, "blocker": "unknown_bridge_mode"}
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
        return 0
    except Exception:
        print(json.dumps({"ok": False, "blocker": "bridge_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())