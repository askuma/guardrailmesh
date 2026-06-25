// src/api.js  —  thin client wrapping every FastAPI endpoint

const BASE = process.env.REACT_APP_API_URL || '';   // '' → uses CRA proxy to :8000

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

export const api = {
  // ── System ──────────────────────────────────────────
  health:           () => req('GET',  '/health'),

  // ── Policies ────────────────────────────────────────
  listPolicies:     ()         => req('GET',    '/policies'),
  getPolicy:        (id)       => req('GET',    `/policies/${id}`),
  createPolicy:     (body)     => req('POST',   '/policies', body),
  updatePolicy:     (id, body) => req('PATCH',  `/policies/${id}`, body),
  deletePolicy:     (id)       => req('DELETE', `/policies/${id}`),
  exportPolicy:     (id, fmt)  => req('GET',    `/policies/${id}/export?format=${fmt}`),
  listTemplates:    ()         => req('GET',    '/policies/templates/list'),
  createFromTemplate: (name)   => req('POST',   `/policies/templates/${name}`),

  // ── Guardrail checks ────────────────────────────────
  checkInput:  (body) => req('POST', '/check/input',  body),
  checkOutput: (body) => req('POST', '/check/output', body),
  checkTool:   (body) => req('POST', '/check/tool',   body),

  // ── A/B Tests ───────────────────────────────────────
  listABTests:   ()       => req('GET',  '/abtests'),
  createABTest:  (body)   => req('POST', '/abtests', body),
  assignABTest:  (id)     => req('GET',  `/abtests/${id}/assign`),

  // ── Observability ───────────────────────────────────
  getMetrics:    () => req('GET', '/metrics'),
  getDashboard:  () => req('GET', '/metrics/dashboard'),
  getAuditLog:   (limit = 50) => req('GET', `/audit?limit=${limit}`),
  getAlerts:     () => req('GET', '/alerts'),
  resolveAlert:  (id) => req('DELETE', `/alerts/${id}`),

  // ── Schema ──────────────────────────────────────────
  getBackends:    () => req('GET', '/schema/backends'),
  getRiskCats:    () => req('GET', '/schema/risk-categories'),
  getActions:     () => req('GET', '/schema/actions'),

  // ── Gap 1: Policy testing ───────────────────────────
  runTests:       (cases) => req('POST', '/test/run', cases),
  runBuiltinTests: (id)   => req('GET',  `/test/builtin/${id}`),

  // ── Gap 3: Decision logging ─────────────────────────
  configureDecisionLog: (cfg) => req('POST', '/decision-log/configure', cfg),
  decisionLogStats:     ()    => req('GET',  '/decision-log/stats'),
  stopDecisionLog:      ()    => req('POST', '/decision-log/stop'),

  // ── Gap 4: Bundle distribution ──────────────────────
  bundlePollerStats: () => req('GET', '/bundles/poller/stats'),
  // export/import use raw fetch (binary) — handled in component

  // ── Gap 5: Versioning ───────────────────────────────
  listVersions:  (id)         => req('GET',  `/policies/${id}/versions`),
  rollbackPolicy: (id, snap)  => req('POST', `/policies/${id}/rollback`, { snapshot_id: snap }),
  versionStats:  ()           => req('GET',  '/versions/stats'),

  // ── Gap 6: Real-time push ───────────────────────────
  pushStats:     () => req('GET', '/push/stats'),
  // SSE stream consumed directly via EventSource in App

  // ── Gap 7: Partial evaluation ───────────────────────
  precompile:    (id, ctx)   => req('POST', `/policies/${id}/precompile`, ctx || {}),
  evaluate:      (id, body)  => req('POST', `/policies/${id}/evaluate`, body),
  precompilerStats: ()       => req('GET',  '/precompiler/stats'),

  // ── Gap 9: Status API ───────────────────────────────
  getStatus:     ()    => req('GET', '/status'),
  getPolicyStatus: (id) => req('GET', `/status/${id}`),

  // ── Gap 10: WASM scorer ─────────────────────────────
  scoreText:     (body) => req('POST', '/score/text', body),

  // ── Gap 11: Data providers ──────────────────────────
  updateBlocklist: (body) => req('POST', '/data-providers/blocklist', body),
  dataProviderStats: ()   => req('GET',  '/data-providers/stats'),
  enrichContext:   (ctx)  => req('POST', '/data-providers/enrich', ctx),

  // ── Red Team ─────────────────────────────────────────
  redteamRun:     (body)   => req('POST', '/redteam/run', body),
  redteamCompare: (body)   => req('POST', '/redteam/compare', body),
  redteamProbes:  (qs='')  => req('GET',  `/redteam/probes${qs}`),
  redteamReport:  (runId)  => req('GET',  `/redteam/reports/${runId}`),
};
