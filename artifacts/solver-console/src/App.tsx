import { useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  Activity,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  Copy,
  LockKeyhole,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Waypoints,
} from 'lucide-react';
import {
  getHealthCheckQueryKey,
  getServiceHealthQueryKey,
  getServiceInfoQueryKey,
  useHealthCheck,
  useServiceHealth,
  useServiceInfo,
} from '@workspace/api-client-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { Route, Switch, useLocation, Router as WouterRouter } from 'wouter';

const queryClient = new QueryClient();

function Home() {
  const [copied, setCopied] = useState(false);
  const runtime = useServiceHealth({
    query: { queryKey: getServiceHealthQueryKey(), refetchInterval: 20_000, retry: 1 },
  });
  const info = useServiceInfo({
    query: { queryKey: getServiceInfoQueryKey(), staleTime: 60_000, retry: 1 },
  });
  const transport = useHealthCheck({
    query: { queryKey: getHealthCheckQueryKey(), refetchInterval: 20_000, retry: 1 },
  });
  const health = runtime.data;
  const ready = health?.status === 'ready';
  const blocked = health?.status === 'blocked';
  const checkedAt = runtime.dataUpdatedAt
    ? new Date(runtime.dataUpdatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : null;

  const copyInfoCommand = async () => {
    try {
      await navigator.clipboard.writeText('curl -sS "$SERVICE_ORIGIN/api/service-info"');
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <main className="min-h-[100dvh] bg-[#f4f2eb] text-[#253a34]">
      <div className="mx-auto min-h-[100dvh] max-w-[1440px] lg:grid lg:grid-cols-[258px_minmax(0,1fr)]">
        <aside className="border-b border-[#deddd3] bg-[#eeece4] px-6 py-5 lg:flex lg:min-h-[100dvh] lg:flex-col lg:border-b-0 lg:border-r lg:px-7 lg:py-8">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-[#285d4c] text-[#f1efe5]">
              <Waypoints size={19} strokeWidth={1.7} />
            </div>
            <div>
              <p className="text-[13px] font-semibold tracking-[-.02em]">Private services</p>
              <p className="mono mt-0.5 text-[10px] uppercase tracking-[.16em] text-[#7c8980]">Operator console</p>
            </div>
          </div>

          <div className="mt-10 hidden lg:block">
            <p className="mono mb-3 px-2 text-[10px] uppercase tracking-[.18em] text-[#839087]">Workspace</p>
            <div className="flex items-center gap-3 rounded-lg bg-[#e4e2d8] px-3 py-3 text-[13px] font-medium">
              <Activity size={16} className="text-[#285d4c]" />
              Service overview
              <span className="ml-auto h-1.5 w-1.5 rounded-full bg-[#285d4c]" />
            </div>
          </div>

          <div className="mt-auto hidden rounded-xl border border-[#d9d8ce] bg-[#f4f2eb] p-4 lg:block">
            <div className="flex items-center gap-2 text-[12px] font-semibold">
              <LockKeyhole size={14} className="text-[#527166]" />
              Private by design
            </div>
            <p className="mt-2 text-[12px] leading-[1.65] text-[#718077]">
              Credentials stay in your bot runtime. This panel never handles solver calls.
            </p>
          </div>
          <div className="mt-5 hidden items-center justify-between text-[10px] text-[#9aa39b] lg:flex">
            <span className="mono">REFERENCE / 01</span>
            <span>Internal</span>
          </div>
        </aside>

        <section className="min-w-0 px-5 pb-12 pt-7 sm:px-8 lg:px-[clamp(36px,6vw,92px)] lg:pt-10">
          <header className="flex items-center justify-between border-b border-[#deddd3] pb-5">
            <div className="flex items-center gap-2 text-[12px] text-[#75827a]">
              <span>Services</span><ChevronRight size={13} />
              <span className="font-medium text-[#253a34]">Solver runtime</span>
            </div>
            <button
              type="button"
              onClick={() => { void runtime.refetch(); void info.refetch(); void transport.refetch(); }}
              className="inline-flex items-center gap-2 rounded-md border border-[#d9d8ce] bg-[#f8f7f1] px-3 py-2 text-[12px] font-medium text-[#4e6258] transition hover:bg-[#ebe9df] focus:outline-none focus:ring-2 focus:ring-[#7a9b8a]"
            >
              <RefreshCw size={13} className={runtime.isFetching ? 'animate-spin' : ''} />
              Refresh status
            </button>
          </header>

          <div className="fade-up mx-auto max-w-[1060px]">
            <div className="relative overflow-hidden border-b border-[#deddd3] py-9 sm:py-12">
              <div className="surface-grid pointer-events-none absolute inset-y-0 right-0 hidden w-[45%] opacity-70 sm:block" />
              <div className="relative">
                <p className="mono text-[10px] uppercase tracking-[.22em] text-[#728177]">Private operator reference <span className="mx-2 text-[#b5b5aa]">/</span> runtime</p>
                <div className="mt-4 flex flex-col justify-between gap-6 sm:flex-row sm:items-end">
                  <div>
                    <h1 className="serif text-[42px] leading-[1.04] tracking-[-.035em] sm:text-[54px]">Solver service</h1>
                    <p className="mt-3 max-w-[520px] text-[14px] leading-6 text-[#6e7c73]">
                      Runtime readiness and safe connection notes for your authorized bot.
                    </p>
                  </div>
                  <StatusPill loading={runtime.isLoading} ready={ready} blocked={blocked} error={runtime.isError} />
                </div>
              </div>
            </div>

            <div className="grid gap-5 py-6 md:grid-cols-[1.35fr_.65fr]">
              <section className={`relative overflow-hidden rounded-xl border p-5 sm:p-6 ${ready ? 'border-[#c9d9ce] bg-[#edf3ec]' : blocked ? 'border-[#e1cbc3] bg-[#f5eeea]' : 'border-[#deddd3] bg-[#eeece4]'}`}>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="mono text-[10px] uppercase tracking-[.18em] text-[#748279]">Runtime readiness</p>
                    <h2 className="serif mt-3 text-[29px] leading-tight tracking-[-.025em]">
                      {runtime.isLoading ? 'Checking runtime' : ready ? 'Ready for authorized calls' : blocked ? 'Runtime blocked' : health?.status ? `Status: ${health.status}` : 'Readiness unknown'}
                    </h2>
                    <p className="mt-2 max-w-[500px] text-[13px] leading-[1.7] text-[#6d7a71]">
                      {runtime.isLoading
                        ? 'Waiting for the live solver health response.'
                        : runtime.isError
                          ? 'The runtime health endpoint could not be reached. Readiness is not confirmed.'
                          : health?.blocker || (ready ? 'The upstream runtime reports ready. This does not guarantee every request will succeed.' : 'Do not route solver work until the service reports ready.')}
                    </p>
                  </div>
                  <div className={`grid h-11 w-11 shrink-0 place-items-center rounded-full ${ready ? 'bg-[#d7e6d7] text-[#285d4c]' : blocked ? 'bg-[#ead8d1] text-[#944e3e]' : 'bg-[#e0dfd5] text-[#758077]'}`}>
                    {ready ? <ShieldCheck size={20} /> : blocked ? <ShieldX size={20} /> : <Activity size={20} />}
                  </div>
                </div>
                <div className="mt-6 flex flex-wrap gap-x-7 gap-y-3 border-t border-current/10 pt-4 text-[11px] text-[#65756b]">
                  <Metric label="Service" value={health?.internal_service === undefined ? '—' : health.internal_service ? 'Internal' : 'External'} />
                  <Metric label="Browser" value={health?.browser || '—'} />
                  <Metric label="Concurrency" value={health?.concurrency_limit == null ? '—' : String(health.concurrency_limit)} />
                  <Metric label="Last checked" value={checkedAt || 'Waiting'} />
                </div>
              </section>

              <section className="rounded-xl border border-[#deddd3] bg-[#f8f7f1] p-5 sm:p-6">
                <div className="flex items-center justify-between">
                  <p className="mono text-[10px] uppercase tracking-[.18em] text-[#748279]">Connection layer</p>
                  <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium ${transport.data ? 'text-[#39705a]' : transport.isError ? 'text-[#a05a48]' : 'text-[#839087]'}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${transport.data ? 'bg-[#4e8b6d]' : transport.isError ? 'bg-[#ae624c]' : 'bg-[#b2b2a8]'}`} />
                    {transport.isLoading ? 'Checking' : transport.data?.status || (transport.isError ? 'Unreachable' : 'Unknown')}
                  </span>
                </div>
                <h2 className="serif mt-5 text-[25px] tracking-[-.02em]">Service response</h2>
                <p className="mt-2 text-[12px] leading-[1.7] text-[#718077]">
                  Lightweight health check confirms the API process is responding. Solver readiness is reported separately.
                </p>
                <div className="mono mt-5 rounded-md bg-[#eeece4] px-3 py-2.5 text-[11px] text-[#52675c]">GET /api/healthz</div>
              </section>
            </div>

            <div className="grid gap-5 lg:grid-cols-[.82fr_1.18fr]">
              <section className="rounded-xl border border-[#deddd3] bg-[#f8f7f1] p-5 sm:p-6">
                <div className="flex items-center gap-2">
                  <span className="grid h-7 w-7 place-items-center rounded-md bg-[#e5e7dc] text-[#527166]"><CircleHelp size={15} /></span>
                  <p className="mono text-[10px] uppercase tracking-[.18em] text-[#748279]">Observed capabilities</p>
                </div>
                <div className="mt-5">
                  <p className="text-[12px] font-semibold text-[#43584e]">Supported types</p>
                  {runtime.isLoading ? <div className="mt-3 h-7 w-2/3 animate-pulse rounded bg-[#e9e7de]" /> : health?.supported_types?.length ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {health.supported_types.map((type) => <span key={type} className="mono rounded-md border border-[#d9d8ce] bg-[#f1f0e9] px-2.5 py-1.5 text-[10px] text-[#52675c]">{type}</span>)}
                    </div>
                  ) : <p className="mt-2 text-[12px] text-[#89938b]">{runtime.isError ? 'Unavailable while health is unreachable.' : 'No supported types reported.'}</p>}
                </div>
                <div className="mt-6 border-t border-[#e4e2d9] pt-4">
                  <p className="text-[12px] font-semibold text-[#43584e]">Runtime limitations</p>
                  {runtime.isLoading ? <div className="mt-3 h-10 animate-pulse rounded bg-[#e9e7de]" /> : health?.limitations?.length ? (
                    <ul className="mt-3 space-y-2.5">
                      {health.limitations.map((limitation, index) => <li key={`${index}-${limitation}`} className="flex gap-2.5 text-[12px] leading-[1.55] text-[#718077]"><span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-[#a17959]" />{limitation}</li>)}
                    </ul>
                  ) : <p className="mt-2 text-[12px] text-[#89938b]">{runtime.isError ? 'Could not retrieve limitations.' : 'No limitations reported by the runtime.'}</p>}
                </div>
              </section>

              <section className="overflow-hidden rounded-xl border border-[#deddd3] bg-[#f8f7f1]">
                <div className="border-b border-[#e3e1d8] px-5 py-4 sm:px-6">
                  <p className="mono text-[10px] uppercase tracking-[.18em] text-[#748279]">Bot integration guide</p>
                  <h2 className="serif mt-2 text-[27px] tracking-[-.02em]">Connect from your runtime</h2>
                  <p className="mt-1 text-[12px] leading-5 text-[#718077]">Keep authentication and all solver traffic server-side, inside your authorized bot.</p>
                </div>
                <div className="space-y-5 p-5 sm:p-6">
                  <GuideStep number="01" title="Read public service info">
                    <p>Inspect the service metadata and request shape before configuring your bot.</p>
                    <CodeBlock code={'curl -sS "$SERVICE_ORIGIN/api/service-info"'} onCopy={copyInfoCommand} copied={copied} />
                  </GuideStep>
                  <GuideStep number="02" title="Call the authenticated solver">
                    <p>Send the bot's supported request to the configured endpoint. Attach authentication from the bot's private runtime configuration; never put credentials in this panel or a browser.</p>
                    <CodeBlock code={`POST ${info.data?.solve_endpoint || '/api/solve'}\nContent-Type: application/json\n\n{ ... bot request ... }`} />
                    <div className="mt-2 flex items-start gap-2 rounded-md bg-[#f0eee6] px-3 py-2.5 text-[11px] leading-[1.55] text-[#748178]">
                      <LockKeyhole size={13} className="mt-0.5 shrink-0 text-[#527166]" />
                      {info.data?.authentication ? 'Authentication is required. Configure it only in the bot runtime secret store.' : 'Use the service-required authentication configured only in the bot runtime secret store.'}
                    </div>
                  </GuideStep>
                  <div className="flex items-center gap-2 border-t border-[#e4e2d9] pt-4 text-[10px] leading-4 text-[#8b958d]">
                    <ShieldCheck size={13} className="shrink-0" />
                    No interactive solving, credential entry, or challenge response display is available here.
                  </div>
                </div>
              </section>
            </div>

            <footer className="mt-7 flex flex-col gap-2 border-t border-[#deddd3] pt-4 text-[10px] text-[#89938b] sm:flex-row sm:items-center sm:justify-between">
              <span>Private operator reference · read-only</span>
              <span className="inline-flex items-center gap-1.5"><Clock3 size={12} /> Health refreshes automatically every 20 seconds</span>
            </footer>
          </div>
        </section>
      </div>
    </main>
  );
}

function StatusPill({ loading, ready, blocked, error }: { loading: boolean; ready?: boolean; blocked?: boolean; error: boolean }) {
  const label = loading ? 'Checking readiness' : ready ? 'Ready' : blocked ? 'Blocked' : error ? 'Health unavailable' : 'Not confirmed';
  const style = ready ? 'border-[#bdd2c2] bg-[#e5efe5] text-[#356b51]' : blocked || error ? 'border-[#e3c6bc] bg-[#f5e9e4] text-[#9a513f]' : 'border-[#dddccf] bg-[#eeece4] text-[#7a8279]';
  return <span className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-2 text-[11px] font-semibold ${style}`}><span className={`h-1.5 w-1.5 rounded-full ${ready ? 'bg-[#4d8966]' : blocked || error ? 'bg-[#ad5c47]' : 'bg-[#9da299]'}`} />{label}</span>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><p className="mono text-[9px] uppercase tracking-[.14em] opacity-70">{label}</p><p className="mt-1 text-[11px] font-medium capitalize">{value}</p></div>;
}

function GuideStep({ number, title, children }: { number: string; title: string; children: ReactNode }) {
  return <div className="grid grid-cols-[30px_1fr] gap-3">
    <span className="mono pt-0.5 text-[10px] text-[#9b8b71]">{number}</span>
    <div><h3 className="text-[12px] font-semibold text-[#43584e]">{title}</h3><div className="mt-1.5 text-[11px] leading-[1.6] text-[#748178]">{children}</div></div>
  </div>;
}

function CodeBlock({ code, onCopy, copied }: { code: string; onCopy?: () => void; copied?: boolean }) {
  return <div className="group relative mt-2.5 overflow-hidden rounded-md bg-[#263a34]">
    <pre className="mono overflow-x-auto whitespace-pre-wrap break-words px-3.5 py-3 pr-12 text-[10px] leading-[1.7] text-[#d8e1d8]">{code}</pre>
    {onCopy && <button type="button" onClick={onCopy} aria-label="Copy service info command" className="absolute right-2 top-2 grid h-7 w-7 place-items-center rounded text-[#adbbb0] transition hover:bg-white/10 hover:text-white">{copied ? <Check size={13} /> : <Copy size={13} />}</button>}
  </div>;
}

function Router() {
  return <RoutedErrorBoundary><Switch><Route path="/" component={Home} /><Route component={NotFound} /></Switch></RoutedErrorBoundary>;
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
        <Router />
      </WouterRouter>
      <Toaster />
    </TooltipProvider>
  </QueryClientProvider>;
}

export default App;