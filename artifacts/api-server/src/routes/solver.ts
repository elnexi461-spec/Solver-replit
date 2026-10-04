import { createHash, timingSafeEqual } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Router, type IRouter, type Request, type Response } from "express";

const router: IRouter = Router();
const artifactDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vendorDir = path.join(artifactDir, "vendor", "captcha-solver-global");
const bridgePath = path.join(artifactDir, "src", "solver_bridge.py");
const pythonPath =
  process.env.PYTHON_EXECUTABLE ??
  (existsSync(path.join(process.cwd(), ".pythonlibs", "bin", "python"))
    ? path.join(process.cwd(), ".pythonlibs", "bin", "python")
    : "python3.11");
const supportedTypes = [
  "turnstile",
  "recaptcha",
  "hcaptcha",
  "cloudflare",
  "awswaf",
  "botguard",
  "datadome",
  "perimeterx",
  "akamai",
  "aliyun",
];
const imageSolverLimitation =
  "Upstream reCAPTCHA and hCaptcha image fallbacks require common/apikey.txt, which is not shipped with the upstream repository and is intentionally not bundled here.";

type BridgeResult = {
  ok?: boolean;
  http_status?: number;
  browser?: string;
  blocker?: string;
  result?: Record<string, unknown>;
  detail?: string;
};

let bridgeBusy = false;
let dispatcherRoundTripVerified = false;
let cachedProbe: { result: BridgeResult; at: number } | undefined;
let pendingProbe: Promise<BridgeResult> | undefined;

function logSafeError(req: Request, event: string) {
  req.log.warn({ event, requestId: req.id }, "Solver API request failed");
}

function isAuthorized(req: Request, res: Response): boolean {
  const expected = process.env.CAPTCHA_API_KEY;
  if (!expected) {
    logSafeError(req, "api_key_not_configured");
    res.status(503).json({ error: "Solver API is not configured." });
    return false;
  }

  const header = req.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  const actual = match?.[1] ?? "";
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  const valid =
    actualBytes.length === expectedBytes.length &&
    timingSafeEqual(
      actualBytes.length === expectedBytes.length ? actualBytes : Buffer.alloc(expectedBytes.length),
      expectedBytes,
    );

  if (!valid) {
    res.status(401).json({ error: "A valid Bearer token is required." });
    return false;
  }
  return true;
}

function spawnBridge(
  mode: "health" | "solve",
  input?: string,
  timeoutMs = 35_000,
): Promise<{ result?: BridgeResult; timedOut: boolean; exitCode: number | null }> {
  return new Promise((resolve) => {
    // Start a private virtual display to preserve the upstream headed-browser defaults.
    // The child group includes the bridge, browser, and Xvfb so timeouts clean them all up.
    const command =
      'display=:$((100 + $$ % 20000)); Xvfb "$display" -screen 0 1920x1080x24 -nolisten tcp >/dev/null 2>&1 & xvfb_pid=$!; trap "kill $xvfb_pid 2>/dev/null || true" EXIT; export DISPLAY="$display"; python_bin="$1"; bridge="$2"; vendor="$3"; mode="$4"; shift 4; "$python_bin" "$bridge" "$mode" "$vendor"';
    const child = spawn(
      "bash",
      ["-lc", command, "solver-api", pythonPath, bridgePath, vendorDir, `--${mode}`],
      {
        cwd: process.cwd(),
        detached: true,
        env: {
          ...process.env,
          PYTHONUNBUFFERED: "1",
          // Xvfb is available; headed mode matches the upstream service configuration.
          TURNSTILE_HEADLESS: process.env.TURNSTILE_HEADLESS ?? "0",
          RECAPTCHA_HEADLESS: process.env.RECAPTCHA_HEADLESS ?? "0",
          HCAPTCHA_HEADLESS: process.env.HCAPTCHA_HEADLESS ?? "0",
        },
        stdio: ["pipe", "pipe", "ignore"],
      },
    );

    let stdout = "";
    let settled = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        if (child.pid) process.kill(-child.pid, "SIGTERM");
      } catch {
        // The child may have exited between the timeout and signal.
      }
      setTimeout(() => {
        try {
          if (child.pid) process.kill(-child.pid, "SIGKILL");
        } catch {
          // The child process group has already exited.
        }
      }, 500).unref();
    }, timeoutMs);

    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      // The bridge emits exactly one bounded JSON response; never retain browser logs.
      if (stdout.length < 2_000_000) stdout += chunk;
    });
    child.on("error", () => {
      clearTimeout(timer);
      settled = true;
      resolve({ timedOut: false, exitCode: null });
    });
    child.on("close", (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      let result: BridgeResult | undefined;
      try {
        result = JSON.parse(stdout.trim()) as BridgeResult;
      } catch {
        // Do not return raw child output: solver/browser errors can contain sensitive data.
      }
      resolve({ result, timedOut, exitCode });
    });

    if (input !== undefined) child.stdin?.end(input);
    else child.stdin?.end();
  });
}

async function getRuntimeHealth(): Promise<BridgeResult> {
  if (cachedProbe && Date.now() - cachedProbe.at < 30_000) return cachedProbe.result;
  if (bridgeBusy) {
    return {
      ok: false,
      browser: "probe deferred while the single solver slot is active",
      blocker: "solver_busy",
    };
  }
  if (pendingProbe) return pendingProbe;

  pendingProbe = (async () => {
    bridgeBusy = true;
    try {
      const run = await spawnBridge("health", undefined, 60_000);
      const result = run.result ?? {
        ok: false,
        browser: "unavailable",
        blocker: run.timedOut ? "health_probe_timed_out" : "health_probe_failed",
      };
      cachedProbe = { result, at: Date.now() };
      return result;
    } finally {
      bridgeBusy = false;
      pendingProbe = undefined;
    }
  })();
  return pendingProbe;
}

const serviceInfo = (_req: Request, res: Response) => {
  res.json({
    name: "Private CAPTCHA Solver API",
    authentication: "POST /api/solve requires Authorization: Bearer <CAPTCHA_API_KEY>.",
    solve_endpoint: "/api/solve",
    health_endpoint: "/api/health",
    source: "https://github.com/0xMissy22/captcha-solver-global",
    request_example: {
      type: "turnstile",
      sitekey: "your-authorized-sitekey",
      url: "https://your-authorized-site.example/",
    },
  });
};

router.get("/", serviceInfo);
router.get("/service-info", serviceInfo);

router.get("/health", async (_req, res) => {
  const runtime = await getRuntimeHealth();
  const ready = runtime.ok === true;
  res.status(ready ? 200 : 503).json({
    status: ready ? "ready" : "blocked",
    internal_service: runtime.ok === true,
    browser: runtime.browser ?? "unavailable",
    dispatcher_round_trip_verified: dispatcherRoundTripVerified,
    concurrency_limit: 1,
    supported_types: supportedTypes,
    limitations: [imageSolverLimitation],
    ...(runtime.blocker ? { blocker: runtime.blocker } : {}),
  });
});

router.post("/solve", async (req, res) => {
  if (!isAuthorized(req, res)) return;

  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    res.status(400).json({ detail: "The request body must be a JSON object." });
    return;
  }
  if (typeof req.body.type !== "string" || !supportedTypes.includes(req.body.type)) {
    res.status(400).json({ detail: "Unsupported solver type." });
    return;
  }
  const timeoutSeconds = req.body.timeout_s ?? 60;
  if (
    !Number.isInteger(timeoutSeconds) ||
    timeoutSeconds < 1 ||
    timeoutSeconds > 240
  ) {
    res.status(400).json({ detail: "timeout_s must be an integer from 1 to 240." });
    return;
  }
  if (bridgeBusy) {
    res.status(429).json({ detail: "The single solver slot is busy; retry later." });
    return;
  }

  bridgeBusy = true;
  const startedAt = Date.now();
  try {
    const run = await spawnBridge("solve", JSON.stringify(req.body), timeoutSeconds * 1000 + 5_000);
    if (run.timedOut) {
      logSafeError(req, "solve_timed_out");
      res.status(408).json({ detail: "Solver deadline exceeded; browser processes were stopped." });
      return;
    }
    if (run.result?.http_status && run.result.http_status !== 200) {
      res.status(run.result.http_status).json({
        detail: run.result.detail ?? "The upstream solver rejected the request.",
      });
      return;
    }
    if (run.exitCode !== 0 || !run.result?.result) {
      logSafeError(req, "upstream_solver_failed");
      res.status(502).json({ detail: "The upstream solver could not complete the request." });
      return;
    }

    dispatcherRoundTripVerified = true;
    const result = run.result.result;
    req.log.info(
      {
        requestId: req.id,
        solverType: req.body.type,
        solved: result.solved === true,
        elapsedMs: Date.now() - startedAt,
      },
      "Upstream solver returned a result",
    );
    res.status(200).json(result);
  } catch {
    logSafeError(req, "internal_solver_error");
    res.status(502).json({ detail: "The upstream solver could not complete the request." });
  } finally {
    bridgeBusy = false;
  }
});

export default router;