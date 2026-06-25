import React, { useState, useEffect, useCallback } from 'react';
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import { api } from './api';

// ─── Colour palette (dark glass) ─────────────────────────────────────────────
const C = {
  bg:       'transparent',
  card:     'rgba(255,255,255,0.06)',
  cardHov:  'rgba(255,255,255,0.1)',
  border:   'rgba(255,255,255,0.11)',
  muted:    'rgba(238,242,255,0.35)',
  sub:      'rgba(238,242,255,0.58)',
  text:     '#eef2ff',
  blue:     '#60a5fa',
  blueDk:   '#3b82f6',
  green:    '#34d399',
  amber:    '#fbbf24',
  red:      '#f87171',
  purple:   '#a78bfa',
  surface:  'rgba(0,0,0,0.3)',
  // Navigation uses same glass
  nav:      'rgba(6,13,31,0.72)',
  navCard:  'rgba(255,255,255,0.04)',
  navBdr:   'rgba(255,255,255,0.08)',
  navText:  '#eef2ff',
  navMuted: 'rgba(238,242,255,0.4)',
};

// ─── Typography ───────────────────────────────────────────────────────────────
const FONT_SANS = "'Fira Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif";
const FONT_MONO = "'Fira Code', 'SFMono-Regular', Consolas, 'Liberation Mono', monospace";

const PIE_COLORS = [C.red, C.amber, C.blue, C.purple, C.green];

// ─── Tiny helpers ────────────────────────────────────────────────────────────
const Badge = ({ children, color = C.green }) => (
  <span style={{
    fontSize: 11, padding: '3px 8px', borderRadius: 4,
    backgroundColor: color + '22', color, fontWeight: 500,
  }}>{children}</span>
);

const GLASS = {
  background: C.card,
  backdropFilter: 'blur(18px)',
  WebkitBackdropFilter: 'blur(18px)',
  border: `1px solid ${C.border}`,
  borderRadius: 14,
};

const Card = ({ children, style }) => (
  <div style={{
    ...GLASS,
    padding: 20,
    boxShadow: '0 4px 32px rgba(0,0,0,0.25)',
    ...style,
  }}>{children}</div>
);

const Btn = ({ children, onClick, variant = 'ghost', disabled }) => {
  const [hov, setHov] = React.useState(false);
  const defs = {
    primary: {
      base:  { background: `linear-gradient(135deg, ${C.blue}, ${C.blueDk})`, color: '#fff', border: `1px solid rgba(96,165,250,0.3)`, boxShadow: `0 0 20px rgba(96,165,250,0.3)` },
      hover: { boxShadow: `0 0 32px rgba(96,165,250,0.5)`, filter: 'brightness(1.1)' },
    },
    danger:  {
      base:  { background: 'rgba(248,113,113,0.1)', color: C.red, border: `1px solid rgba(248,113,113,0.3)` },
      hover: { background: 'rgba(248,113,113,0.2)', borderColor: 'rgba(248,113,113,0.55)', boxShadow: '0 0 16px rgba(248,113,113,0.2)' },
    },
    ghost:   {
      base:  { background: 'rgba(255,255,255,0.07)', color: C.sub, border: `1px solid ${C.border}` },
      hover: { background: 'rgba(255,255,255,0.13)', color: C.text, borderColor: 'rgba(255,255,255,0.2)' },
    },
  };
  const { base, hover } = defs[variant] || defs.ghost;
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => !disabled && setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        padding: '7px 16px', borderRadius: 8, fontSize: 13, fontWeight: 500,
        fontFamily: FONT_SANS, letterSpacing: '0.01em',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        transition: 'background 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease',
        ...base,
        ...(hov && !disabled ? hover : {}),
      }}
    >{children}</button>
  );
};

const Input = ({ label, ...props }) => (
  <label style={{ display: 'block', marginBottom: 12 }}>
    <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: C.muted, display: 'block', marginBottom: 5 }}>{label}</span>
    <input {...props} style={{
      width: '100%', padding: '9px 12px', borderRadius: 8,
      border: `1px solid ${C.border}`,
      background: 'rgba(0,0,0,0.25)',
      backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)',
      color: C.text, fontSize: 13, outline: 'none', fontFamily: FONT_SANS,
      transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
    }}
    onFocus={e => { e.target.style.borderColor = C.blue; e.target.style.boxShadow = `0 0 0 3px ${C.blue}30`; }}
    onBlur={e =>  { e.target.style.borderColor = C.border; e.target.style.boxShadow = 'none'; }}
    />
  </label>
);

const Select = ({ label, children, ...props }) => (
  <label style={{ display: 'block', marginBottom: 12 }}>
    <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: C.muted, display: 'block', marginBottom: 5 }}>{label}</span>
    <select {...props} style={{
      width: '100%', padding: '9px 12px', borderRadius: 8,
      border: `1px solid ${C.border}`,
      background: 'rgba(0,0,0,0.3)',
      backdropFilter: 'blur(8px)', WebkitBackdropFilter: 'blur(8px)',
      color: C.text, fontSize: 13, outline: 'none', fontFamily: FONT_SANS,
      transition: 'border-color 0.15s ease',
    }}>{children}</select>
  </label>
);

// ─── Stat card (glass with glow) ─────────────────────────────────────────────
const StatCard = ({ label, value, sub, color = C.blue }) => {
  const [hov, setHov] = React.useState(false);
  return (
    <div
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        ...GLASS,
        padding: '20px 22px',
        position: 'relative',
        overflow: 'hidden',
        background: hov ? C.cardHov : C.card,
        boxShadow: `0 4px 32px rgba(0,0,0,0.25), 0 0 40px ${color}25`,
        transform: hov ? 'translateY(-2px)' : 'none',
        transition: 'transform 0.2s ease, background 0.2s ease, box-shadow 0.2s ease',
      }}
    >
      {/* Top accent line */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color, borderRadius: '14px 14px 0 0' }} />
      {/* Glow orb */}
      <div style={{
        position: 'absolute', right: -10, top: -10,
        width: 80, height: 80,
        background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
        opacity: 0.18, pointerEvents: 'none',
      }} />
      <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: C.muted, margin: '0 0 10px', position: 'relative' }}>{label}</p>
      <p style={{ fontFamily: FONT_MONO, fontSize: 28, fontWeight: 700, color, margin: '0 0 5px', lineHeight: 1, position: 'relative', filter: `drop-shadow(0 0 8px ${color})` }}>{value ?? '—'}</p>
      {sub && <p style={{ fontSize: 11, color: C.muted, margin: 0, position: 'relative' }}>{sub}</p>}
    </div>
  );
};

// ─── Section header ──────────────────────────────────────────────────────────
const SectionHead = ({ title, action }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
    <h2 style={{ fontFamily: FONT_MONO, fontSize: 16, fontWeight: 600, color: C.text, margin: 0, letterSpacing: '-0.01em' }}>{title}</h2>
    {action}
  </div>
);

// ─── Modal shell ─────────────────────────────────────────────────────────────
const Modal = ({ title, onClose, children }) => (
  <div style={{
    position: 'fixed', inset: 0, backgroundColor: 'rgba(15,23,42,0.7)',
    backdropFilter: 'blur(4px)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
  }}>
    <div style={{
      backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 12,
      boxShadow: '0 20px 60px rgba(0,0,0,0.2)',
      padding: 28, width: 480, maxHeight: '90vh', overflowY: 'auto',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
        <h3 style={{ fontFamily: FONT_MONO, color: C.text, fontSize: 16, fontWeight: 600 }}>{title}</h3>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.muted, fontSize: 20, cursor: 'pointer' }}>×</button>
      </div>
      {children}
    </div>
  </div>
);

// ─── Toast ───────────────────────────────────────────────────────────────────
const Toast = ({ msg, type }) => (
  <div style={{
    position: 'fixed', bottom: 24, right: 24, zIndex: 200,
    backgroundColor: type === 'error' ? C.red : C.green,
    color: '#fff', padding: '10px 18px', borderRadius: 8,
    fontSize: 13, fontWeight: 500, boxShadow: '0 4px 20px #0006',
  }}>{msg}</div>
);

// ═════════════════════════════════════════════════════════════════════════════
// TABS
// ═════════════════════════════════════════════════════════════════════════════

// ── Overview ─────────────────────────────────────────────────────────────────
function OverviewTab({ metrics, dashboard, health }) {
  // Build trend data from raw metrics object (keys → time-series)
  const metricsHistory = [
    { time: '−5m', checks: 80,  passRate: 88, latency: 44 },
    { time: '−4m', checks: 95,  passRate: 85, latency: 47 },
    { time: '−3m', checks: 110, passRate: 90, latency: 43 },
    { time: '−2m', checks: 102, passRate: 87, latency: 50 },
    { time: '−1m', checks: 120, passRate: 89, latency: 45 },
    { time: 'now', checks: metrics?.total_checks ?? 0, passRate: metrics ? Math.round((metrics.passed / (metrics.total_checks || 1)) * 100) : 0, latency: 46 },
  ];

  const byBackend = metrics?.by_backend
    ? Object.entries(metrics.by_backend).map(([name, val]) => ({ name, checks: val }))
    : [];

  const byAction = metrics?.by_action
    ? Object.entries(metrics.by_action).map(([name, val], i) => ({ name, value: val, fill: PIE_COLORS[i % PIE_COLORS.length] }))
    : [];

  const passRate = metrics?.total_checks
    ? ((metrics.passed / metrics.total_checks) * 100).toFixed(1)
    : '—';

  const blockedPct = metrics?.total_checks
    ? (((metrics.total_checks - metrics.passed) / metrics.total_checks) * 100).toFixed(1)
    : '—';

  return (
    <div>
      {/* KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 16, marginBottom: 24 }}>
        <StatCard label="Total Checks"  value={metrics?.total_checks?.toLocaleString() ?? '0'} sub="all time" color={C.blue}   />
        <StatCard label="Pass Rate"     value={passRate === '—' ? '—' : passRate + '%'}         sub="checks passed" color={C.green}  />
        <StatCard label="Blocked"       value={metrics?.blocked?.toLocaleString() ?? '0'}       sub={blockedPct + '% of total'} color={C.red}    />
        <StatCard label="API Status"    value={health?.status === 'ok' ? 'Healthy' : 'Down'}    sub={`${health?.policies_loaded ?? 0} policies loaded`} color={health?.status === 'ok' ? C.green : C.red} />
      </div>

      {/* Trend + Action pie */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Check Volume &amp; Pass Rate</h3>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={metricsHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="time" stroke={C.muted} tick={{ fontSize: 11 }} />
              <YAxis yAxisId="l" stroke={C.muted} tick={{ fontSize: 11 }} />
              <YAxis yAxisId="r" orientation="right" stroke={C.muted} tick={{ fontSize: 11 }} domain={[0, 100]} />
              <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line yAxisId="l" type="monotone" dataKey="checks"   stroke={C.blue}  name="Checks" dot={false} strokeWidth={2} />
              <Line yAxisId="r" type="monotone" dataKey="passRate" stroke={C.green} name="Pass %" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Actions Taken</h3>
          {byAction.length ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={byAction} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                    {byAction.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 8 }}>
                {byAction.map((e, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: C.sub }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: e.fill }} />
                    {e.name} ({e.value})
                  </div>
                ))}
              </div>
            </>
          ) : <p style={{ color: C.muted, fontSize: 13, textAlign: 'center', paddingTop: 60 }}>No data yet — run some guardrail checks</p>}
        </Card>
      </div>

      {/* Backend breakdown */}
      {byBackend.length > 0 && (
        <Card style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Checks by Backend</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={byBackend}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="name" stroke={C.muted} tick={{ fontSize: 12 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, fontSize: 12 }} />
              <Bar dataKey="checks" fill={C.blue} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}
    </div>
  );
}

// ── Policies ─────────────────────────────────────────────────────────────────
function PoliciesTab({ toast }) {
  const [policies, setPolicies]       = useState({});
  const [templates, setTemplates]     = useState([]);
  const [backends, setBackends]       = useState([]);
  const [riskCats, setRiskCats]       = useState([]);
  const [actions, setActions]         = useState([]);
  const [showCreate, setShowCreate]   = useState(false);
  const [loading, setLoading]         = useState(false);

  const [form, setForm] = useState({
    name: '', description: '', backend: 'guardrails_ai',
    risk_categories: ['prompt_injection'],
    sensitivity: 'medium', action_on_violation: 'block',
  });

  const load = useCallback(async () => {
    const [p, t, b, r, a] = await Promise.all([
      api.listPolicies(), api.listTemplates(),
      api.getBackends(), api.getRiskCats(), api.getActions(),
    ]);
    setPolicies(p); setTemplates(t.templates);
    setBackends(b.backends); setRiskCats(r.risk_categories); setActions(a.actions);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!form.name) return;
    setLoading(true);
    try {
      await api.createPolicy(form);
      toast('Policy created', 'ok');
      setShowCreate(false);
      load();
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  const handleFromTemplate = async (name) => {
    try {
      await api.createFromTemplate(name);
      toast(`Created from template: ${name}`, 'ok');
      load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this policy?')) return;
    try {
      await api.deletePolicy(id);
      toast('Policy deleted', 'ok');
      load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const toggleRiskCat = (cat) => {
    setForm(f => ({
      ...f,
      risk_categories: f.risk_categories.includes(cat)
        ? f.risk_categories.filter(c => c !== cat)
        : [...f.risk_categories, cat],
    }));
  };

  return (
    <div>
      <SectionHead title="Policies" action={<Btn variant="primary" onClick={() => setShowCreate(true)}>+ New Policy</Btn>} />

      {/* Templates */}
      <Card style={{ marginBottom: 20 }}>
        <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>Quick-start from a template:</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {templates.map(t => (
            <Btn key={t.name} onClick={() => handleFromTemplate(t.name)}>
              {t.name.replace(/_/g, ' ')}
            </Btn>
          ))}
        </div>
      </Card>

      {/* Policy list */}
      {Object.keys(policies).length === 0
        ? <p style={{ color: C.muted, textAlign: 'center', padding: 40 }}>No policies yet. Create one above.</p>
        : Object.values(policies).map(p => (
          <Card key={p.id} style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{p.name}</span>
                  <Badge color={p.enabled ? C.green : C.muted}>{p.enabled ? 'Active' : 'Disabled'}</Badge>
                  <Badge color={C.blue}>{p.backend}</Badge>
                </div>
                <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                  Sensitivity: {p.sensitivity} · Action: {p.action_on_violation} · Tags: {p.tags?.join(', ') || '—'}
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <Btn variant="danger" onClick={() => handleDelete(p.id)}>Delete</Btn>
              </div>
            </div>
          </Card>
        ))
      }

      {/* Create modal */}
      {showCreate && (
        <Modal title="Create Policy" onClose={() => setShowCreate(false)}>
          <Input label="Name *" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Production Chat Policy" />
          <Input label="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          <Select label="Backend" value={form.backend} onChange={e => setForm(f => ({ ...f, backend: e.target.value }))}>
            {backends.map(b => <option key={b} value={b}>{b}</option>)}
          </Select>
          <Select label="Sensitivity" value={form.sensitivity} onChange={e => setForm(f => ({ ...f, sensitivity: e.target.value }))}>
            {['low', 'medium', 'high'].map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select label="Action on violation" value={form.action_on_violation} onChange={e => setForm(f => ({ ...f, action_on_violation: e.target.value }))}>
            {actions.map(a => <option key={a} value={a}>{a}</option>)}
          </Select>
          <div style={{ marginBottom: 16 }}>
            <p style={{ fontSize: 12, color: C.sub, marginBottom: 8 }}>Risk categories</p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {riskCats.map(cat => {
                const active = form.risk_categories.includes(cat);
                return (
                  <button key={cat} onClick={() => toggleRiskCat(cat)} style={{
                    padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                    border: `1px solid ${active ? C.blue : C.border}`,
                    backgroundColor: active ? C.blue + '22' : 'transparent',
                    color: active ? C.blue : C.muted,
                  }}>{cat.replace(/_/g, ' ')}</button>
                );
              })}
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Btn onClick={() => setShowCreate(false)}>Cancel</Btn>
            <Btn variant="primary" onClick={handleCreate} disabled={loading || !form.name}>
              {loading ? 'Creating…' : 'Create'}
            </Btn>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Live check tester ─────────────────────────────────────────────────────────
function CheckerTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selectedPolicy, setSelectedPolicy] = useState('');
  const [checkType, setCheckType] = useState('input');
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listPolicies().then(p => {
      setPolicies(p);
      const first = Object.keys(p)[0];
      if (first) setSelectedPolicy(first);
    });
  }, []);

  const run = async () => {
    if (!selectedPolicy || !text) return;
    setLoading(true); setResult(null);
    try {
      const fn = checkType === 'input' ? api.checkInput : api.checkOutput;
      const res = await fn({ text, policy_id: selectedPolicy });
      setResult(res);
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <SectionHead title="Live Guardrail Tester" />
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
          <Select label="Policy" value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)}>
            {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Select label="Check type" value={checkType} onChange={e => setCheckType(e.target.value)}>
            <option value="input">Input check</option>
            <option value="output">Output check</option>
          </Select>
        </div>
        <label style={{ display: 'block', marginBottom: 12 }}>
          <span style={{ fontSize: 12, color: C.sub, display: 'block', marginBottom: 4 }}>Text to check</span>
          <textarea value={text} onChange={e => setText(e.target.value)}
            rows={4} placeholder="Type or paste text here…"
            style={{
              width: '100%', padding: '8px 10px', borderRadius: 6,
              border: `1px solid ${C.border}`, backgroundColor: C.bg,
              color: C.text, fontSize: 13, resize: 'vertical', outline: 'none',
            }} />
        </label>
        <Btn variant="primary" onClick={run} disabled={loading || !text || !selectedPolicy}>
          {loading ? 'Checking…' : 'Run check'}
        </Btn>
      </Card>

      {result && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <span style={{ fontSize: 24 }}>{result.passed ? '✅' : '🚫'}</span>
            <div>
              <p style={{ fontSize: 16, fontWeight: 700, color: result.passed ? C.green : C.red, margin: 0 }}>
                {result.passed ? 'Passed' : 'Blocked / Modified'}
              </p>
              <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                {result.latency_ms?.toFixed(1)}ms · backend: {result.backend_used} · request: {result.request_id?.slice(0, 8)}
              </p>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px' }}>Risk score</p>
              <div style={{ background: C.bg, borderRadius: 6, height: 6, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${result.risk_score * 100}%`, backgroundColor: result.risk_score > 0.6 ? C.red : result.risk_score > 0.3 ? C.amber : C.green, transition: 'width .4s' }} />
              </div>
              <p style={{ fontSize: 12, color: C.text, marginTop: 4 }}>{(result.risk_score * 100).toFixed(0)}%</p>
            </div>
            <div>
              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px' }}>Action taken</p>
              <Badge color={result.action === 'allow' ? C.green : result.action === 'block' ? C.red : C.amber}>
                {result.action}
              </Badge>
            </div>
          </div>
          {result.detected_risks?.length > 0 && (
            <div>
              <p style={{ fontSize: 11, color: C.sub, marginBottom: 6 }}>Detected risks</p>
              {result.detected_risks.map((r, i) => (
                <div key={i} style={{ fontSize: 12, color: C.red, padding: '3px 0' }}>
                  ⚠ {typeof r === 'object' ? JSON.stringify(r) : r}
                </div>
              ))}
            </div>
          )}
          {result.modified_text && result.modified_text !== text && (
            <div style={{ marginTop: 12, padding: 12, backgroundColor: C.bg, borderRadius: 6 }}>
              <p style={{ fontSize: 11, color: C.sub, marginBottom: 4 }}>Modified output</p>
              <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{result.modified_text}</p>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// ── Alerts ───────────────────────────────────────────────────────────────────
function AlertsTab({ toast }) {
  const [alerts, setAlerts] = useState([]);

  const load = useCallback(() => {
    api.getAlerts().then(r => setAlerts(r.active_alerts));
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  const resolve = async (id) => {
    try { await api.resolveAlert(id); toast('Alert resolved', 'ok'); load(); }
    catch (e) { toast(e.message, 'error'); }
  };

  return (
    <div>
      <SectionHead title={`Alerts (${alerts.length} active)`} action={<Btn onClick={load}>Refresh</Btn>} />
      {alerts.length === 0
        ? <Card><p style={{ color: C.muted, textAlign: 'center', padding: 32 }}>✅ No active alerts</p></Card>
        : alerts.map(a => (
          <Card key={a.id} style={{
            marginBottom: 12,
            borderLeft: `4px solid ${a.severity === 'critical' ? C.red : C.amber}`,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{a.title}</span>
                  <Badge color={a.severity === 'critical' ? C.red : C.amber}>{a.severity}</Badge>
                </div>
                <p style={{ fontSize: 12, color: C.muted, margin: '0 0 4px' }}>{a.type}</p>
                <p style={{ fontSize: 12, color: C.sub, margin: 0 }}>
                  Value: <b style={{ color: C.text }}>{a.metric_value}</b> · Threshold: {a.threshold}
                </p>
              </div>
              <Btn onClick={() => resolve(a.id)}>Resolve</Btn>
            </div>
          </Card>
        ))
      }
    </div>
  );
}

// ── A/B Tests ────────────────────────────────────────────────────────────────
function ABTestsTab({ toast }) {
  const [tests, setTests]         = useState({});
  const [policies, setPolicies]   = useState({});
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', control_policy_id: '', experiment_policy_id: '', traffic_split: 0.5, duration_hours: 24 });

  const load = useCallback(async () => {
    const [t, p] = await Promise.all([api.listABTests(), api.listPolicies()]);
    setTests(t); setPolicies(p);
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    try { await api.createABTest(form); toast('A/B test created', 'ok'); setShowCreate(false); load(); }
    catch (e) { toast(e.message, 'error'); }
  };

  const assign = async (id) => {
    try {
      const r = await api.assignABTest(id);
      toast(`Assigned → ${r.policy_name}`, 'ok');
    } catch (e) { toast(e.message, 'error'); }
  };

  const policyList = Object.values(policies);

  return (
    <div>
      <SectionHead title="A/B Tests" action={<Btn variant="primary" onClick={() => setShowCreate(true)}>+ New Test</Btn>} />
      {Object.keys(tests).length === 0
        ? <Card><p style={{ color: C.muted, textAlign: 'center', padding: 32 }}>No A/B tests yet.</p></Card>
        : Object.values(tests).map(t => {
          const ctrl = policies[t.control_policy_id];
          const exp  = policies[t.experiment_policy_id];
          return (
            <Card key={t.id} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div>
                  <p style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 8px' }}>{t.name}</p>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 8 }}>
                    <div>
                      <p style={{ fontSize: 11, color: C.sub, margin: '0 0 2px' }}>Control</p>
                      <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{ctrl?.name ?? t.control_policy_id.slice(0, 8)}</p>
                    </div>
                    <div>
                      <p style={{ fontSize: 11, color: C.sub, margin: '0 0 2px' }}>Experiment</p>
                      <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{exp?.name ?? t.experiment_policy_id.slice(0, 8)}</p>
                    </div>
                  </div>
                  <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                    Split: {(t.traffic_split * 100).toFixed(0)}% experiment · {t.duration_hours}h duration
                  </p>
                </div>
                <Btn onClick={() => assign(t.id)}>Assign request</Btn>
              </div>
            </Card>
          );
        })
      }

      {showCreate && (
        <Modal title="Create A/B Test" onClose={() => setShowCreate(false)}>
          <Input label="Test name *" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <Select label="Control policy" value={form.control_policy_id} onChange={e => setForm(f => ({ ...f, control_policy_id: e.target.value }))}>
            <option value="">Select…</option>
            {policyList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Select label="Experiment policy" value={form.experiment_policy_id} onChange={e => setForm(f => ({ ...f, experiment_policy_id: e.target.value }))}>
            <option value="">Select…</option>
            {policyList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Input label="Traffic split (0–1)" type="number" min="0.1" max="0.9" step="0.1"
            value={form.traffic_split} onChange={e => setForm(f => ({ ...f, traffic_split: parseFloat(e.target.value) }))} />
          <Input label="Duration (hours)" type="number" min="1"
            value={form.duration_hours} onChange={e => setForm(f => ({ ...f, duration_hours: parseInt(e.target.value) }))} />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Btn onClick={() => setShowCreate(false)}>Cancel</Btn>
            <Btn variant="primary" onClick={create} disabled={!form.name || !form.control_policy_id || !form.experiment_policy_id}>Create</Btn>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Audit log ────────────────────────────────────────────────────────────────
function AuditTab() {
  const [entries, setEntries] = useState([]);
  const [limit, setLimit] = useState(50);

  useEffect(() => {
    api.getAuditLog(limit).then(r => setEntries(r.entries ?? []));
  }, [limit]);

  return (
    <div>
      <SectionHead title="Audit Log" action={
        <Select label="" value={limit} onChange={e => setLimit(Number(e.target.value))} style={{ marginBottom: 0 }}>
          {[20, 50, 100, 200].map(n => <option key={n} value={n}>Last {n}</option>)}
        </Select>
      } />
      <Card>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Timestamp', 'Policy', 'Action', 'Passed', 'Risk', 'Backend', 'Latency'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: C.muted }}>No audit entries yet</td></tr>
              ) : entries.slice().reverse().map((e, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                  <td style={{ padding: '8px 12px', color: C.muted }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ padding: '8px 12px', color: C.sub, fontFamily: FONT_MONO }}>{e.policy_id?.slice(0, 8)}…</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.action}</td>
                  <td style={{ padding: '8px 12px' }}>
                    <Badge color={e.passed ? C.green : C.red}>{e.passed ? 'yes' : 'no'}</Badge>
                  </td>
                  <td style={{ padding: '8px 12px', color: e.risk_score > 0.6 ? C.red : C.sub }}>
                    {typeof e.risk_score === 'number' ? (e.risk_score * 100).toFixed(0) + '%' : '—'}
                  </td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.backend ?? '—'}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.latency_ms?.toFixed(1) ?? '—'}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ── Testing tab (Gap 1) ──────────────────────────────────────────────────────
function TestingTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selected, setSelected] = useState('');
  const [report, setReport]     = useState(null);
  const [loading, setLoading]   = useState(false);

  useEffect(() => {
    api.listPolicies().then(p => {
      setPolicies(p);
      const first = Object.keys(p)[0];
      if (first) setSelected(first);
    });
  }, []);

  const runBuiltin = async () => {
    if (!selected) return;
    setLoading(true); setReport(null);
    try {
      setReport(await api.runBuiltinTests(selected));
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <SectionHead title="Policy Testing" />
      <Card style={{ marginBottom: 16 }}>
        <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>
          Run the built-in adversarial smoke suite (safe queries, injection, jailbreak, SQL, code exec) against a policy.
        </p>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <Select label="Policy" value={selected} onChange={e => setSelected(e.target.value)}>
              {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </div>
          <div style={{ marginBottom: 12 }}>
            <Btn variant="primary" onClick={runBuiltin} disabled={loading || !selected}>
              {loading ? 'Running…' : 'Run test suite'}
            </Btn>
          </div>
        </div>
      </Card>

      {report && (
        <Card>
          <div style={{ display: 'flex', gap: 24, marginBottom: 16 }}>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Pass rate</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: report.pass_rate === 100 ? C.green : C.amber }}>{report.pass_rate}%</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Passed</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: C.green }}>{report.passed}</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Failed</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: report.failed ? C.red : C.muted }}>{report.failed}</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Duration</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: C.blue }}>{report.duration_ms?.toFixed(0)}ms</p></div>
          </div>
          <div style={{ display: 'grid', gap: 6 }}>
            {report.results.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', backgroundColor: C.bg, borderRadius: 6 }}>
                <span style={{ fontSize: 16 }}>{r.passed ? '✅' : '❌'}</span>
                <span style={{ fontSize: 13, color: C.text, flex: 1 }}>{r.name}</span>
                {r.risk_score != null && (
                  <span style={{ fontSize: 12, color: r.risk_score > 0.6 ? C.red : C.muted }}>risk {(r.risk_score * 100).toFixed(0)}%</span>
                )}
                {r.failures?.length > 0 && (
                  <span style={{ fontSize: 11, color: C.red }}>{r.failures.join('; ')}</span>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── Status & Metrics tab (Gaps 8, 9, 11) ─────────────────────────────────────
function StatusTab({ toast }) {
  const [status, setStatus]   = useState(null);
  const [dpStats, setDpStats] = useState(null);
  const [blockUser, setBlockUser] = useState('');

  const load = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([api.getStatus(), api.dataProviderStats()]);
      setStatus(s); setDpStats(d);
    } catch (e) {}
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, [load]);

  const addBlock = async () => {
    if (!blockUser) return;
    try {
      await api.updateBlocklist({ users: [blockUser] });
      toast(`Blocked user: ${blockUser}`, 'ok');
      setBlockUser(''); load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const policies = status ? Object.values(status.policies) : [];

  return (
    <div>
      <SectionHead title="Status & Health" action={<Btn onClick={load}>Refresh</Btn>} />

      {status && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))', gap: 16, marginBottom: 20 }}>
          <StatCard label="Tracked policies" value={status.total_policies} color={C.blue} />
          <StatCard label="Healthy" value={status.healthy_policies} sub="zero errors" color={C.green} />
          <StatCard label="Prometheus" value="/metrics" sub="scrape endpoint live" color={C.purple} />
        </div>
      )}

      <Card style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>Per-policy status (OPA status API parity)</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {['Policy', 'Backend', 'Checks', 'Blocked', 'Errors', 'Avg', 'p95', 'Last check'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {policies.length === 0 ? (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: 24, color: C.muted }}>No checks recorded yet — run some in Live Test</td></tr>
              ) : policies.map((p, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                  <td style={{ padding: '8px 12px', color: C.text }}>{p.policy_name}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.backend}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.total_checks}</td>
                  <td style={{ padding: '8px 12px', color: p.total_blocked ? C.amber : C.sub }}>{p.total_blocked}</td>
                  <td style={{ padding: '8px 12px', color: p.error_count ? C.red : C.sub }}>{p.error_count}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.avg_latency_ms}ms</td>
                  <td style={{ padding: '8px 12px', color: p.p95_latency_ms > 100 ? C.amber : C.sub }}>{p.p95_latency_ms}ms</td>
                  <td style={{ padding: '8px 12px', color: C.muted }}>{p.last_check_at ? new Date(p.last_check_at).toLocaleTimeString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>External data providers (blocklist)</h3>
        {dpStats && (
          <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>
            Providers: {dpStats.providers?.join(', ') || 'none'} · {dpStats.call_count} enrich calls · {dpStats.error_count} errors
          </p>
        )}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input value={blockUser} onChange={e => setBlockUser(e.target.value)}
            placeholder="user_id to block"
            style={{ flex: 1, padding: '8px 10px', borderRadius: 6, border: `1px solid ${C.border}`, backgroundColor: C.bg, color: C.text, fontSize: 13, outline: 'none' }} />
          <Btn variant="primary" onClick={addBlock} disabled={!blockUser}>Add to blocklist</Btn>
        </div>
      </Card>
    </div>
  );
}

// ── Versions & Bundles tab (Gaps 4, 5) ───────────────────────────────────────
function VersionsTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selected, setSelected] = useState('');
  const [versions, setVersions] = useState([]);

  const loadPolicies = useCallback(async () => {
    const p = await api.listPolicies();
    setPolicies(p);
    const first = Object.keys(p)[0];
    if (first && !selected) setSelected(first);
  }, [selected]);

  useEffect(() => { loadPolicies(); }, [loadPolicies]);

  const loadVersions = useCallback(async () => {
    if (!selected) return;
    try {
      const r = await api.listVersions(selected);
      setVersions(r.versions || []);
    } catch (e) { setVersions([]); }
  }, [selected]);

  useEffect(() => { loadVersions(); }, [loadVersions]);

  const rollback = async (snapId) => {
    if (!window.confirm('Roll back to this snapshot?')) return;
    try {
      await api.rollbackPolicy(selected, snapId);
      toast('Rolled back', 'ok');
      loadVersions();
    } catch (e) { toast(e.message, 'error'); }
  };

  const exportBundle = () => {
    const base = process.env.REACT_APP_API_URL || '';
    window.open(`${base}/bundles/export`, '_blank');
  };

  return (
    <div>
      <SectionHead title="Versions & Bundles" action={<Btn variant="primary" onClick={exportBundle}>↓ Export bundle (.tar.gz)</Btn>} />

      <Card style={{ marginBottom: 16 }}>
        <Select label="Policy" value={selected} onChange={e => setSelected(e.target.value)}>
          {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </Select>
      </Card>

      <Card>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>Version history (newest first)</h3>
        {versions.length === 0 ? (
          <p style={{ color: C.muted, fontSize: 13, textAlign: 'center', padding: 24 }}>
            No snapshots yet. Snapshots are created automatically on policy create/update.
          </p>
        ) : (
          <div style={{ display: 'grid', gap: 8 }}>
            {versions.map((v, i) => (
              <div key={v.snapshot_id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', backgroundColor: C.bg, borderRadius: 6 }}>
                <Badge color={i === 0 ? C.green : C.muted}>{i === 0 ? 'current' : `v${versions.length - i}`}</Badge>
                <div style={{ flex: 1 }}>
                  <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{v.change_reason || 'no reason given'}</p>
                  <p style={{ fontSize: 11, color: C.muted, margin: 0 }}>
                    {new Date(v.created_at).toLocaleString()} · by {v.created_by} · {v.snapshot_id.slice(0, 8)}
                  </p>
                </div>
                {i !== 0 && <Btn onClick={() => rollback(v.snapshot_id)}>Roll back</Btn>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ═════════════════════════════════════════════════════════════════════════════
const TABS = [
  { id: 'overview',  label: 'Overview'  },
  { id: 'checker',   label: 'Live Test'  },
  { id: 'policies',  label: 'Policies'  },
  { id: 'testing',   label: 'Testing'   },
  { id: 'status',    label: 'Status'    },
  { id: 'versions',  label: 'Versions'  },
  { id: 'alerts',    label: 'Alerts'    },
  { id: 'abtests',   label: 'A/B Tests' },
  { id: 'audit',     label: 'Audit Log' },
];

export default function App() {
  const [tab, setTab]         = useState('overview');
  const [metrics, setMetrics] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [health, setHealth]   = useState(null);
  const [toast, setToast]     = useState(null);
  const [lastEvent, setLastEvent] = useState(null);

  const showToast = (msg, type = 'ok') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const loadGlobal = useCallback(async () => {
    // Health is checked independently so a failure in metrics/dashboard
    // never leaves the status indicator stuck.
    try {
      const h = await api.health();
      setHealth(h);
    } catch {
      setHealth({ status: 'down' });
    }
    try {
      const [m, d] = await Promise.all([api.getMetrics(), api.getDashboard()]);
      setMetrics(m); setDashboard(d);
    } catch {}
  }, []);

  useEffect(() => {
    loadGlobal();
    // Poll fast (3s) until the API is reachable, then back off to 15s.
    let interval = 3000;
    let timer;
    const tick = async () => {
      await loadGlobal();
      timer = setTimeout(tick, interval);
    };
    timer = setTimeout(tick, interval);
    // Switch to slow polling once we've had a successful health check
    const slow = setInterval(() => { interval = 15000; }, 6000);
    return () => { clearTimeout(timer); clearInterval(slow); };
  }, [loadGlobal]);

  // Gap 6 — real-time policy push via Server-Sent Events
  useEffect(() => {
    const base = process.env.REACT_APP_API_URL || '';
    let es;
    try {
      es = new EventSource(`${base}/push/events`);
      es.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data);
          if (ev.type && ev.type !== 'connected') {
            setLastEvent(ev);
            loadGlobal();   // refresh on any policy change
          }
        } catch {}
      };
      es.onerror = () => { /* browser auto-reconnects */ };
    } catch {}
    return () => { if (es) es.close(); };
  }, [loadGlobal]);

  return (
    <div style={{ color: C.text, minHeight: '100vh', fontFamily: FONT_SANS }}>
      {/* Header — sticky glass bar */}
      <div style={{
        position: 'sticky', top: 0, zIndex: 50,
        background: C.nav,
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        borderBottom: `1px solid ${C.navBdr}`,
        padding: '14px 32px',
        boxShadow: '0 4px 40px rgba(0,0,0,0.4)',
      }}>
        <div style={{ maxWidth: 1300, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            {/* Logo mark */}
            <div style={{
              width: 38, height: 38, borderRadius: 9,
              background: `linear-gradient(135deg, ${C.blue}, ${C.blueDk})`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              boxShadow: `0 0 18px ${C.blue}55`,
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <polyline points="9 12 11 14 15 10"/>
              </svg>
            </div>
            <div>
              <h1 style={{ fontFamily: FONT_MONO, fontSize: 18, fontWeight: 700, margin: 0, color: C.navText, letterSpacing: '-0.01em' }}>
                Guardrail Control Center
              </h1>
              <p style={{ fontSize: 11, color: C.navMuted, margin: 0, letterSpacing: '0.02em' }}>
                Unified AI safety monitoring · 10 backends + custom endpoint
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            {lastEvent && (
              <span style={{
                fontSize: 11, color: '#c4b5fd',
                backgroundColor: 'rgba(167,139,250,0.15)',
                padding: '3px 10px', borderRadius: 5,
                border: '1px solid rgba(167,139,250,0.25)',
                fontFamily: FONT_MONO,
              }}>
                ⚡ {lastEvent.type}
              </span>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 7, height: 7, borderRadius: '50%',
                backgroundColor: health?.status === 'ok' ? '#10b981' : '#ef4444',
                boxShadow: `0 0 7px ${health?.status === 'ok' ? '#10b981' : '#ef4444'}`,
              }} />
              <span style={{ fontSize: 12, color: C.navMuted, fontWeight: 500 }}>
                {health?.status === 'ok' ? 'API Online' : 'API Offline'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Tab bar — glass underline style */}
      <div style={{
        background: C.navCard,
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: `1px solid ${C.navBdr}`,
        display: 'flex', gap: 0, padding: '0 32px', overflowX: 'auto',
      }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            padding: '11px 16px', fontSize: 12, whiteSpace: 'nowrap',
            fontFamily: FONT_SANS, fontWeight: tab === t.id ? 600 : 400,
            color: tab === t.id ? C.navText : C.navMuted,
            borderBottom: tab === t.id ? `2px solid ${C.blue}` : '2px solid transparent',
            letterSpacing: '0.01em',
            transition: 'color 0.15s ease, border-color 0.15s ease',
          }}>{t.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ maxWidth: 1300, margin: '0 auto', padding: '28px 24px 80px' }}>
        {tab === 'overview' && <OverviewTab metrics={metrics} dashboard={dashboard} health={health} />}
        {tab === 'checker'  && <CheckerTab  toast={showToast} />}
        {tab === 'policies' && <PoliciesTab toast={showToast} />}
        {tab === 'testing'  && <TestingTab  toast={showToast} />}
        {tab === 'status'   && <StatusTab   toast={showToast} />}
        {tab === 'versions' && <VersionsTab toast={showToast} />}
        {tab === 'alerts'   && <AlertsTab   toast={showToast} />}
        {tab === 'abtests'  && <ABTestsTab  toast={showToast} />}
        {tab === 'audit'    && <AuditTab />}
      </div>

      {toast && <Toast msg={toast.msg} type={toast.type} />}
    </div>
  );
}
