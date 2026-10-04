     1|"""Captcha solver HTTP sidecar — unified endpoints."""
     2|import asyncio
     3|import ipaddress
     4|import itertools
     5|import logging
     6|import os
     7|import socket
     8|import time
     9|from collections import deque
    10|from typing import Any, Optional
    11|from urllib.parse import urlparse
    12|
    13|from fastapi import Body, Depends, FastAPI, HTTPException, Query
    14|from fastapi.security import HTTPBearer
    15|from pydantic import BaseModel, Field
    16|
    17|logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    18|log = logging.getLogger("captcha-solver")
    19|
    20|_DESCRIPTION = """
    21|Local captcha-solving HTTP sidecar built on **CloakBrowser** (self-hosted anti-detect
    22|Chromium). Solves challenges by driving them in a real browser engine.
    23|
    24|**Supported:** Turnstile · reCAPTCHA (v2 / v3 / invisible, incl. Enterprise) · hCaptcha ·
    25|Cloudflare clearance (`cf_clearance` — full-page Managed / JS challenge) ·
    26|AWS WAF (`aws-waf-token` — silent JS challenge).
    27|
    28|Dispatch is by the `type` field of `POST /solve`; optional fields select the variant
    29|(`version`, `real_page`, `verify_url`, …). `/health` is public; behind the public
    30|domain every other path needs a Bearer token (enforced at the Caddy layer).
    31|
    32|Caller-supplied URLs (`url`, `verify_url`, `page_url`, `post_fetch[].url`) are fetched
    33|from the browser session and are **SSRF-guarded**: private/loopback/link-local targets
    34|are rejected unless `SOLVER_ALLOW_PRIVATE=1`.
    35|"""
    36|
    37|_TAGS = [
    38|    {"name": "solve", "description": "Solve a captcha challenge."},
    39|    {"name": "monitoring", "description": "Liveness, current tasks, recent solve log."},
    40|]
    41|
    42|# Public base URL shown in the OpenAPI docs (contact + servers dropdown). The repo ships a
    43|# neutral placeholder; the live service injects its real domain at runtime via SOLVER_PUBLIC_URL.
    44|_PUBLIC_URL = os.getenv("SOLVER_PUBLIC_URL", "https://solver.example.com")
    45|
    46|app = FastAPI(
    47|    title="Captcha Solver",
    48|    description=_DESCRIPTION,
    49|    version="1.0.0",
    50|    openapi_tags=_TAGS,
    51|    contact={"name": "solver", "url": _PUBLIC_URL},
    52|    servers=[
    53|        {"url": _PUBLIC_URL, "description": "Public (Bearer token required)"},
    54|        {"url": "http://127.0.0.1:8877", "description": "Local (no auth)"},
    55|    ],
    56|    swagger_ui_parameters={
    57|        "docExpansion": "list",
    58|        "persistAuthorization": True,     # keep the Bearer token across reloads
    59|        "tryItOutEnabled": True,
    60|        "displayRequestDuration": True,
    61|        "filter": True,
    62|    },
    63|)
    64|
    65|# Non-enforcing Bearer scheme: makes Swagger UI show an Authorize button and forward the
    66|# token on "Try it out". auto_error=False means a missing/malformed token yields None and
    67|# the endpoint proceeds — real enforcement stays at the Caddy layer (public domain only).
    68|_bearer = HTTPBearer(auto_error=False, description="Bearer token (required on the public "
    69|                     "domain; enforced by the reverse proxy). Ignored for local calls.")
    70|SUPPORTED = ["turnstile", "recaptcha", "hcaptcha", "cloudflare", "awswaf", "botguard", "datadome", "perimeterx", "akamai", "aliyun"]
    71|# Page-level solvers that harvest a cookie/token from the live page (no sitekey needed).
    72|_PAGE_LEVEL = ("cloudflare", "awswaf", "botguard", "datadome", "perimeterx", "akamai")
    73|# Solvers that supply their own canonical URL (caller need not pass `url`).
    74|# datadome is NOT here: the caller passes the DataDome-fronted url (+ referer) itself.
    75|_SELF_URL = ("botguard", "perimeterx", "aliyun")
    76|# Allow private/loopback targets only when explicitly opted in (dev/testing).
    77|_ALLOW_PRIVATE = os.getenv("SOLVER_ALLOW_PRIVATE") == "1"
    78|
    79|# ── Monitoring ring buffer ───────────────────────────────────────────
    80|_solve_log = deque(maxlen=100)
    81|# Concurrent solves of different types can run at once (per-type locks), so track
    82|# current tasks by id rather than a single global that they'd clobber.
    83|_solve_current: dict = {}
    84|_task_ids = itertools.count(1)
    85|
    86|
    87|def _is_solved(result: dict) -> bool:
    88|    """The ONE success predicate for every solver type — the single source of truth for
    89|    the injected `solved` field + logs. Token solvers signal via truthy `token`, realpage
    90|    variants via `verify_success`, page-level cookie solvers via `success`/`cf_clearance`;
    91|    a truthy value in ANY of these = solved.
    92|    """
    93|    return bool(result.get("token") or result.get("cf_clearance")
    94|                or result.get("verify_success") or result.get("success"))
    95|
    96|
    97|def _log_solve(type_: str, sitekey: Optional[str], url: str, result: dict):
    98|    """Push a solve event to the ring buffer."""
    99|    sitekey = sitekey or ""  # cloudflare has no sitekey
   100|    solved = _is_solved(result)
   101|    _solve_log.appendleft({
   102|        "type": type_,
   103|        "sitekey": sitekey[:12] + ("..." if len(sitekey) > 12 else ""),
   104|        "url": url[:60] + ("..." if len(url) > 60 else ""),
   105|        "token": solved,
   106|        "error": result.get("error"),
   107|        "elapsed": result.get("elapsed"),
   108|        "method": result.get("method"),
   109|        "timestamp": time.time(),
   110|        "success": solved and not result.get("error"),
   111|    })
   112|
   113|
   114|def _assert_public_url(raw: str, field: str):
   115|    """Reject non-http(s) schemes and private/loopback/link-local/reserved hosts.
   116|
   117|    Guards the SSRF surface: /solve navigates and fetches caller-supplied URLs from
   118|    the server's browser session (credentials:'include'). ponytail: validate-then-
   119|    fetch has a DNS-rebinding TOCTOU window; add pinned resolution if it matters.
   120|    """
   121|    if not raw:
   122|        return
   123|    u = urlparse(raw)
   124|    if u.scheme not in ("http", "https"):
   125|        raise HTTPException(400, f"{field}: only http/https URLs allowed")
   126|    host = u.hostname
   127|    if not host:
   128|        raise HTTPException(400, f"{field}: URL has no host")
   129|    if _ALLOW_PRIVATE:
   130|        return
   131|    try:
   132|        infos = socket.getaddrinfo(host, None)
   133|    except socket.gaierror:
   134|        raise HTTPException(400, f"{field}: host does not resolve")
   135|    for info in infos:
   136|        ip = ipaddress.ip_address(info[4][0])
   137|        if (ip.is_private or ip.is_loopback or ip.is_link_local
   138|                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
   139|            raise HTTPException(400, f"{field}: private/loopback host blocked")
   140|
   141|
   142|def _validate_urls(req: "SolveRequest"):
   143|    _assert_public_url(req.url, "url")
   144|    _assert_public_url(req.verify_url, "verify_url")
   145|    _assert_public_url(req.page_url, "page_url")
   146|    for pf in (req.post_fetch or []):
   147|        _assert_public_url(pf.url, "post_fetch.url")
   148|
   149|
   150|class PreAction(BaseModel):
   151|    """One UI step to run before the captcha appears (real_page mode)."""
   152|    type: str = Field(..., description="click | fill | select | press | wait",
   153|                      examples=["click"])
   154|    selector: Optional[str] = Field(
   155|        None, description="Target selector. Formats: CSS (default), XPath (//…), "
   156|        "text=…, regex=…, role=name[name='…']", examples=["text=Continue with Email"])
   157|    value: Optional[str] = Field(
   158|        None, description="Value for fill/select/press, or seconds for wait")
   159|    timeout: Optional[int] = Field(10000, description="Element wait timeout (ms)")
   160|
   161|
   162|class PostFetch(BaseModel):
   163|    """An API call fired from the SAME browser session after solving."""
   164|    url: str = Field(..., description="Endpoint to call (SSRF-guarded, same as top-level url)",
   165|                     examples=["https://target.com/api/verify"])
   166|    method: Optional[str] = Field("POST", examples=["POST"])
   167|    body: Optional[dict] = Field(
   168|        None, description="JSON body. Use the literal __TOKEN__ anywhere to inject the "
   169|        "solved token.", examples=[{"token": "__TOKEN__"}])
   170|
   171|
   172|class SolveRequest(BaseModel):
   173|    # Required
   174|    type: str = Field(..., description="Captcha type — dispatch key.",
   175|                      examples=["turnstile"])
   176|    sitekey: Optional[str] = Field(
   177|        None, description="Site key from the target page. Required for turnstile/recaptcha/"
   178|        "hcaptcha; not used for type=cloudflare (page-level clearance).",
   179|        examples=["0x4AAAAAAA..."])
   180|    url: Optional[str] = Field(None, description="Page the captcha is on (also the intercept origin). "
   181|                     "Required for all types except botguard (which defaults to the Google sign-in page).",
   182|                     examples=["https://target.com"])
   183|
   184|    # All-captcha optional
   185|    action: Optional[str] = Field(
   186|        None, description="Turnstile action, or reCAPTCHA v3/invisible action. "
   187|        "For hCaptcha, the literal \"invisible\" selects the invisible-execute path.")
   188|    cdata: Optional[str] = Field(None, description="Turnstile customer data bound into the token.")
   189|    real_page: Optional[bool] = Field(
   190|        False, description="Solve on the live target page (navigate + drive) instead of a stub.")
   191|    timeout_s: Optional[int] = Field(
   192|        60, description="Overall solve deadline (seconds). Enforced server-side; on expiry the "
   193|        "call returns 408 and the browser is released.")
   194|    pre_actions: Optional[list[PreAction]] = Field(None, description="Steps to run before solving (real_page).")
   195|    post_fetch: Optional[list[PostFetch]] = Field(None, description="API calls after solving (real_page).")
   196|    proxy: Optional[str] = Field(
   197|        None, description="Per-request proxy (scheme://user:pass@host:port). Honored for "
   198|        "type=cloudflare and type=awswaf (overrides the shared TURNSTILE_PROXY env fallback); "
   199|        "their cookies are IP-bound, so replay from this same proxy IP. For turnstile/recaptcha "
   200|        "set TURNSTILE_PROXY / RECAPTCHA_PROXY instead — the per-request field is not wired for "
   201|        "those.")
   202|
   203|    # reCAPTCHA-only
   204|    version: Optional[str] = Field(None, description="reCAPTCHA only: v2 | v3 | invisible (default v2).")
   205|    secret: Optional[str] = Field(None, description="reCAPTCHA v3 only: target's secret key, to also return the score.")
   206|    enterprise: Optional[bool] = Field(False, description="reCAPTCHA only: load enterprise.js / grecaptcha.enterprise.")
   207|
   208|    # solve-and-verify (turnstile)
   209|    verify_url: Optional[str] = Field(None, description="Turnstile: verify the token from the same session at this URL.")
   210|    verify_payload: Optional[dict] = Field(None, description="Turnstile: body for verify_url; token is injected as \"token\".")
   211|    page_url: Optional[str] = Field(None, description="Turnstile: origin to intercept (defaults to verify_url).")
   212|
   213|    # botguard-only (Google OAuth token extraction)
   214|    email: Optional[str] = Field(None, description="BotGuard: account email to enter — drives the sign-in flow to the token-bearing RPC.")
   215|    password: Optional[str] = Field(None, description="BotGuard: optional password — if set, drives to the password step and grabs the B4hajb hard-gate token instead of the MI613e lookup token.")
   216|
   217|    # datadome-only (DataDome bot-management clearance cookie)
   218|    referer: Optional[str] = Field(None, description="datadome: optional framing Referer so DataDome serves the same config/scoring as the real flow. The caller supplies its own site's referer (e.g. https://github.com/ when harvesting via octocaptcha). Pair with a `url` pointing at the DataDome-fronted page that loads tags.js.")
   219|
   220|    # perimeterx-only (HUMAN/PerimeterX 'Press & Hold')
   221|    render_flow: Optional[str] = Field(None, description="perimeterx: named site trigger that makes the gate render when it doesn't show on plain load (default 'outlook_signup'). Throwaway navigation only — NOT account creation. Pass null with a `url` for deployments whose gate renders on goto(). Harvests the _px3 clearance cookie (bound to _pxvid+IP+UA; replay under the same proxy+UA within TTL).")
   222|
   223|    # aliyun-only (Aliyun Captcha 2.0 slide-puzzle). No sitekey — the challenge identity
   224|    # is scene_id + prefix (prefix selects the captcha-open endpoint). Harvest-only:
   225|    # returns {sceneId, certifyId, deviceToken, data}; the caller replays it immediately
   226|    # into VerifyCaptchaV3 (token is session-bound + one-time-use, deviceToken time-bound).
   227|    scene_id: Optional[str] = Field(None, description="aliyun: the SceneId of the target site's captcha (e.g. read from the page config). Required for type=aliyun.")
   228|    prefix: Optional[str] = Field(None, description="aliyun: the captcha-open endpoint prefix (e.g. '13lbkb5' -> <prefix>.captcha-open-southeast.aliyuncs.com). Required for type=aliyun.")
   229|    region: Optional[str] = Field(None, description="aliyun: captcha region — 'sgp' (default), 'cn', or 'intl'.")
   230|
   231|
   232|# Named request examples → Swagger UI renders these as a dropdown picker on /solve.
   233|_SOLVE_EXAMPLES = {
   234|    "turnstile": {
   235|        "summary": "Turnstile (route-intercept)",
   236|        "value": {"type": "turnstile", "sitekey": "0x4AAAAAAA...", "url": "https://target.com"},
   237|    },
   238|    "recaptcha_v3": {
   239|        "summary": "reCAPTCHA v3 Enterprise (score)",
   240|        "value": {"type": "recaptcha", "version": "v3", "enterprise": True,
   241|                  "sitekey": "6Lc...", "url": "https://target.com", "action": "login"},
   242|    },
   243|    "recaptcha_v2": {
   244|        "summary": "reCAPTCHA v2 checkbox",
   245|        "value": {"type": "recaptcha", "version": "v2", "sitekey": "6Lf...", "url": "https://target.com/form"},
   246|    },
   247|    "hcaptcha": {
   248|        "summary": "hCaptcha (checkbox)",
   249|        "value": {"type": "hcaptcha", "sitekey": "10000000-ffff-ffff-ffff-000000000001",
   250|                  "url": "https://target.com"},
   251|    },
   252|    "turnstile_realpage": {
   253|        "summary": "Turnstile on the live page (pre_actions + post_fetch)",
   254|        "value": {"type": "turnstile", "real_page": True, "url": "https://app.example.com/login",
   255|                  "pre_actions": [{"type": "fill", "selector": "input[type=email]", "value": "u@ex.com"},
   256|                                  {"type": "click", "selector": "button[type=submit]"}],
   257|                  "post_fetch": [{"url": "https://app.example.com/api/verify",
   258|                                  "body": {"token": "__TOKEN__"}}]},
   259|    },
   260|    "cloudflare_clearance": {
   261|        "summary": "Cloudflare clearance (cf_clearance — Managed or JS challenge)",
   262|        "value": {"type": "cloudflare", "url": "https://protected.example.com",
   263|                  "proxy": "http://user:***@ip:port"},
   264|    },
   265|    "aws_waf": {
   266|        "summary": "AWS WAF token (silent JS challenge → aws-waf-token)",
   267|        "value": {"type": "awswaf", "url": "https://protected.example.com/waitlist",
   268|                  "proxy": "http://user:***@ip:port"},
   269|    },
   270|    "botguard": {
   271|        "summary": "BotGuard (Google OAuth bgRequest token + session cookies)",
   272|        "value": {"type": "botguard", "email": "user@example.com",
   273|                  "password": "optional-for-hard-gate-token"},
   274|    },
   275|    "datadome": {
   276|        "summary": "DataDome clearance cookie — caller passes the DataDome-fronted url (+ referer)",
   277|        "value": {"type": "datadome",
   278|                  "url": "https://octocaptcha.com/datadome?origin_page=github_signup_redesign",
   279|                  "referer": "https://github.com/",
   280|                  "proxy": "http://user:***@ip:port"},
   281|    },
   282|    "akamai": {
   283|        "summary": "Harvest an Akamai Bot Manager _abck clearance cookie (caller passes the Akamai-fronted url)",
   284|        "value": {"type": "akamai",
   285|                  "url": "https://www.example-akamai-site.com/",
   286|                  "proxy": "http://user:***@ip:port"},
   287|    },
   288|    "perimeterx": {
   289|        "summary": "PerimeterX/HUMAN 'Press & Hold' → harvest _px3 clearance cookie (render_flow trigger)",
   290|        "value": {"type": "perimeterx", "render_flow": "outlook_signup",
   291|                  "proxy": "http://user:***@ip:port"},
   292|    },
   293|}
   294|
   295|
   296|# ── Response models (documentation shapes; solvers return supersets) ──
   297|class SolveResponse(BaseModel):
   298|    type: str = Field(..., description="Echoes the request type — the dispatch discriminator.",
   299|                      examples=["turnstile"])
   300|    solved: bool = Field(..., description="THE success signal. True iff the captcha was solved, "
   301|                         "uniform across every type — read this instead of branching per-type.")
   302|    token: Optional[str] = Field(None, description="Solved token for token types (turnstile/"
   303|                                 "recaptcha/hcaptcha). Absent for type=cloudflare (see cf_clearance); "
   304|                                 "empty string on a failed/realpage solve — trust `solved`, not this.")
   305|    method: Optional[str] = Field(None, description="Which path solved it (route | execute | real-page | image | …).")
   306|    elapsed: Optional[float] = Field(None, description="Solve time (seconds).")
   307|    error: Optional[str] = Field(None, description="Set when the solve failed but returned 200.")
   308|    # Per-type success/detail discriminators (present only for their type):
   309|    verify_success: Optional[bool] = Field(None, description="realpage variants: token harvested + verified.")
   310|    success: Optional[bool] = Field(None, description="Page-level (cloudflare/awswaf): cookie obtained.")
   311|    cf_clearance: Optional[dict] = Field(None, description="type=cloudflare: the cf_clearance cookie record.")
   312|    model_config = {"extra": "allow"}  # solvers add expires_in, score, cookies, user_agent, post_fetch, …
   313|
   314|
   315|class ErrorResponse(BaseModel):
   316|    detail: str = Field(..., description="Human-readable error message")
   317|
   318|
   319|# Schematized non-2xx responses for /solve (422 is auto-documented by FastAPI).
   320|_SOLVE_ERROR_RESPONSES = {
   321|    400: {"model": ErrorResponse, "description": "Bad request — unsupported type, missing sitekey for a widget type, or an SSRF-rejected URL"},
   322|    408: {"model": ErrorResponse, "description": "Global deadline (timeout_s) exceeded before a result"},
   323|    500: {"model": ErrorResponse, "description": "Unhandled solver error"},
   324|}
   325|
   326|
   327|class HealthResponse(BaseModel):
   328|    status: str = Field(examples=["ok"])
   329|    supported_types: list[str] = Field(examples=[["turnstile", "recaptcha", "hcaptcha"]])
   330|
   331|
   332|class StatusResponse(BaseModel):
   333|    services: dict[str, str]
   334|    current: list[dict[str, Any]] = Field(description="Currently running solve tasks.")
   335|
   336|
   337|class LogsResponse(BaseModel):
   338|    logs: list[dict[str, Any]]
   339|    total: int
   340|
   341|
   342|@app.get("/health", response_model=HealthResponse, tags=["monitoring"],
   343|         operation_id="health",
   344|         summary="Liveness + supported types (public, no auth)")
   345|async def health():
   346|    """Public liveness probe. Lists the captcha types this service can solve."""
   347|    return {"status": "ok", "supported_types": SUPPORTED}
   348|
   349|
   350|def _extract(req: SolveRequest):
   351|    """Unpack pre_actions + post_fetch for realpage endpoints."""
   352|    actions = [a.model_dump() for a in req.pre_actions] if req.pre_actions else None
   353|    fetches = [f.model_dump() for f in req.post_fetch] if req.post_fetch else None
   354|    return actions, fetches
   355|
   356|
   357|async def _dispatch(req: SolveRequest) -> dict:
   358|    """Run the actual solver for req.type/version and return its result dict.
   359|
   360|    Result always carries a top-level "type"; the caller logs + returns it.
   361|    """
   362|    if req.type == "turnstile":
   363|        from turnstile.solve import solve_turnstile, solve_and_verify, solve_turnstile_realpage
   364|        # route-intercept turnstile raises TimeoutError on no-token; catch it here so an
   365|        # unsolved turnstile returns a uniform 200 {error}, not a collision with the real
   366|        # asyncio deadline (408).
   367|        try:
   368|            if req.verify_url and req.verify_payload:
   369|                r = await solve_and_verify(
   370|                    req.sitekey, req.verify_url, req.verify_payload, req.action,
   371|                    cdata=req.cdata, page_url=req.page_url)
   372|            elif req.real_page:
   373|                actions, fetches = _extract(req)
   374|                r = await solve_turnstile_realpage(
   375|                    req.url, req.sitekey, req.timeout_s, actions, fetches)
   376|            else:
   377|                r = await solve_turnstile(req.sitekey, req.url, req.action, req.cdata)
   378|        except TimeoutError as e:
   379|            r = {"token": "", "error": str(e), "method": "route"}
   380|        return {"type": "turnstile", **r}
   381|
   382|    if req.type == "hcaptcha":
   383|        from hcaptcha.solve import solve_hcaptcha, solve_hcaptcha_invisible, solve_hcaptcha_realpage
   384|        if req.action == "invisible":
   385|            r = await solve_hcaptcha_invisible(req.sitekey, req.url)
   386|        elif req.real_page:
   387|            actions, fetches = _extract(req)
   388|            r = await solve_hcaptcha_realpage(
   389|                req.url, req.sitekey, req.timeout_s, actions, fetches)
   390|        else:
   391|            r = await solve_hcaptcha(req.sitekey, req.url)
   392|        return {"type": "hcaptcha", **r}
   393|
   394|    if req.type == "cloudflare":
   395|        from cloudflare.solve import solve_cf_clearance
   396|        actions, fetches = _extract(req)
   397|        r = await solve_cf_clearance(req.url, req.proxy, req.timeout_s, actions, fetches)
   398|        return {"type": "cloudflare", **r}
   399|
   400|    if req.type == "awswaf":
   401|        from awswaf.solve import solve_aws_waf
   402|        actions, fetches = _extract(req)
   403|        r = await solve_aws_waf(req.url, req.proxy, req.timeout_s, actions, fetches)
   404|        return {"type": "awswaf", **r}
   405|
   406|    if req.type == "botguard":
   407|        from botguard.solve import solve_botguard
   408|        actions, _ = _extract(req)
   409|        r = await solve_botguard(
   410|            url=req.url, email=req.email, password=req.password,
   411|            proxy=req.proxy, timeout_s=req.timeout_s or 90, pre_actions=actions)
   412|        return {"type": "botguard", **r}
   413|
   414|    if req.type == "datadome":
   415|        from datadome.solve import solve_datadome
   416|        r = await solve_datadome(
   417|            url=req.url, referer=req.referer,
   418|            proxy=req.proxy, timeout_s=req.timeout_s or 60)
   419|        return {"type": "datadome", **r}
   420|
   421|    if req.type == "perimeterx":
   422|        from perimeterx.solve import solve_perimeterx
   423|        r = await solve_perimeterx(
   424|            url=req.url, render_flow=req.render_flow or "outlook_signup",
   425|            proxy=req.proxy, timeout_s=req.timeout_s or 200)
   426|        return {"type": "perimeterx", **r}
   427|
   428|    if req.type == "akamai":
   429|        from akamai.solve import solve_akamai
   430|        actions, fetches = _extract(req)
   431|        r = await solve_akamai(req.url, req.proxy, req.timeout_s or 90, actions, fetches)
   432|        return {"type": "akamai", **r}
   433|
   434|    if req.type == "aliyun":
   435|        from aliyun.solve import solve_aliyun
   436|        r = await solve_aliyun(
   437|            scene_id=req.scene_id, prefix=req.prefix, region=req.region or "sgp",
   438|            proxy=req.proxy, timeout_s=req.timeout_s or 90)
   439|        return {"type": "aliyun", **r}
   440|
   441|    # reCAPTCHA
   442|    from recaptcha.solve import (
   443|        solve_recaptcha_v3, solve_recaptcha_v3_realpage, solve_recaptcha_invisible,
   444|        solve_recaptcha_v2, solve_recaptcha_v2_realpage,
   445|    )
   446|    version = req.version or "v2"  # default v2 (checkbox)
   447|    if version == "v3":
   448|        if req.real_page:
   449|            actions, _ = _extract(req)
   450|            r = await solve_recaptcha_v3_realpage(
   451|                req.url, req.sitekey, req.action or "submit",
   452|                enterprise=req.enterprise, timeout_s=req.timeout_s, pre_actions=actions)
   453|        else:
   454|            r = await solve_recaptcha_v3(
   455|                req.sitekey, req.url, req.action or "submit",
   456|                req.secret, enterprise=req.enterprise)
   457|    elif version == "invisible":
   458|        r = await solve_recaptcha_invisible(
   459|            req.sitekey, req.url, req.action or "submit", enterprise=req.enterprise)
   460|    elif version == "v2":
   461|        if req.real_page:
   462|            actions, fetches = _extract(req)
   463|            r = await solve_recaptcha_v2_realpage(
   464|                req.url, req.sitekey, actions, fetches, timeout_s=req.timeout_s)
   465|        else:
   466|            r = await solve_recaptcha_v2(req.sitekey, req.url, enterprise=req.enterprise)
   467|    else:
   468|        raise HTTPException(400, f"Unknown version: {version}. Use v3|invisible|v2")
   469|    return {"type": "recaptcha", **r}
   470|
   471|
   472|@app.post("/solve", response_model=SolveResponse, tags=["solve"],
   473|          operation_id="solve",
   474|          dependencies=[Depends(_bearer)],
   475|          summary="Solve a captcha (dispatch by type)",
   476|          responses=_SOLVE_ERROR_RESPONSES)
   477|async def solve(req: SolveRequest = Body(..., openapi_examples=_SOLVE_EXAMPLES)):
   478|    """Solve any supported captcha and return the token.
   479|
   480|    Dispatch is by `type`; the variant is selected by optional fields:
   481|
   482|    - **Turnstile** — default route-intercept; `verify_url`+`verify_payload` to
   483|      solve-and-verify; `real_page:true` to drive the live page (pre_actions/post_fetch).
   484|    - **reCAPTCHA** — `version`: `v2` (checkbox + Mistral image fallback, `real_page` supported),
   485|      `v3` (score; pass `secret` to also return the score), `invisible`. `enterprise:true`
   486|      for Enterprise keys.
   487|    - **hCaptcha** — default checkbox (Mistral image/drag fallback); `action:"invisible"`
   488|      for the execute path; `real_page:true` for the live page.
   489|    - **cloudflare** — pass the full-page Cloudflare interstitial (Managed or JS challenge)
   490|      and return the `cf_clearance` cookie + `user_agent` + all cookies. No `sitekey`;
   491|      pass `proxy` so the cookie is bound to a replayable IP. See the README for the
   492|      replay contract (IP + JA3 + UA must match).
   493|    - **awswaf** — navigate an AWS-WAF-protected URL, let the silent JS challenge set
   494|      `aws-waf-token`, and return it + `user_agent` + all cookies. No `sitekey`; pass
   495|      `proxy` (same IP-bound replay contract as cloudflare). Silent challenge only —
   496|      no interactive visual-puzzle support.
   497|
   498|    **Success signal:** every response carries a uniform top-level `solved` bool — read
   499|    it and don't branch per-type. Type-specific detail still rides along (`token`,
   500|    `cf_clearance`, `score`, `expires_in`, `cookies`, `user_agent`, `post_fetch`, …).
   501|