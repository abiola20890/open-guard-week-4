import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { NetStatsResponse, NetRule, NetEventsResponse, Event } from '../api';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';

// ─── Constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#2563eb',
  info:     '#475569',
};

const SEVERITY_BG: Record<string, string> = {
  critical: '#450a0a',
  high:     '#431407',
  medium:   '#422006',
  low:      '#1e3a5f',
  info:     '#1e293b',
};

const TIER_COLORS: Record<string, string> = {
  T0: '#334155',
  T1: '#1d4ed8',
  T2: '#d97706',
  T3: '#ea580c',
  T4: '#dc2626',
};

const TIER_BG: Record<string, string> = {
  T0: '#1e293b',
  T1: '#1e3a5f',
  T2: '#422006',
  T3: '#431407',
  T4: '#450a0a',
};

const PROTO_COLORS: Record<string, string> = {
  TCP:  '#3b82f6',
  UDP:  '#8b5cf6',
  DNS:  '#22c55e',
  ICMP: '#f59e0b',
  HTTP: '#06b6d4',
  HTTPS:'#10b981',
};

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const bg    = SEVERITY_BG[severity]    ?? SEVERITY_BG.info;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {severity}
    </span>
  );
}

// ─── Tier badge ───────────────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: number | string }) {
  const t = typeof tier === 'number' ? `T${tier}` : String(tier);
  const color = TIER_COLORS[t] ?? TIER_COLORS.T0;
  const bg    = TIER_BG[t]    ?? TIER_BG.T0;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700 }}>
      {t}
    </span>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="card stat-card">
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontSize: '0.7rem', color: '#334155', marginTop: '0.125rem' }}>{sub}</div>}
    </div>
  );
}

// ─── Threat bar ───────────────────────────────────────────────────────────────

function ThreatBar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div style={{ marginBottom: '0.625rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
        <span style={{ color: '#cbd5e1', textTransform: 'capitalize' }}>{label.replace(/_/g, ' ')}</span>
        <span style={{ color: '#94a3b8' }}>{count}</span>
      </div>
      <div style={{ background: '#0f172a', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
        <div style={{ height: '100%', borderRadius: '4px', width: `${pct}%`, background: color, transition: 'width 0.5s ease' }} />
      </div>
    </div>
  );
}

// ─── Tier distribution ────────────────────────────────────────────────────────

function TierDistribution({ breakdown }: { breakdown: Record<string, number> }) {
  const tiers = ['T0', 'T1', 'T2', 'T3', 'T4'];
  const total = tiers.reduce((s, t) => s + (breakdown[t] ?? 0), 0) || 1;
  return (
    <div>
      <div style={{ display: 'flex', borderRadius: '4px', overflow: 'hidden', height: '12px', marginBottom: '0.75rem', background: '#0f172a' }}>
        {tiers.map((t) => {
          const pct = ((breakdown[t] ?? 0) / total) * 100;
          return pct > 0 ? (
            <div key={t} style={{ width: `${pct}%`, background: TIER_COLORS[t] }} title={`${t}: ${breakdown[t] ?? 0}`} />
          ) : null;
        })}
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {tiers.map((t) => (
          <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: TIER_COLORS[t], display: 'inline-block' }} />
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              {t}: <strong style={{ color: '#e2e8f0' }}>{breakdown[t] ?? 0}</strong>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Event field helpers ──────────────────────────────────────────────────────

function evEventType(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  return (meta?.['event_type'] as string | undefined) ?? (ev['type'] as string | undefined) ?? '—';
}

function evProtocol(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  return (meta?.['protocol'] as string | undefined) ?? '—';
}

function evDirection(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  return (meta?.['direction'] as string | undefined) ?? '—';
}

function evDestPort(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  const p = meta?.['dest_port'];
  return p !== undefined ? String(p) : '—';
}

function evBlocked(ev: Event): boolean {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  return Boolean(meta?.['blocked']);
}

function evSourceIP(ev: Event): string {
  return (ev['source'] as string | undefined) ?? '—';
}

function formatTs(ts: string | undefined): string {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function NetworkGuard() {
  const [stats, setStats] = useState<NetStatsResponse | null>(null);
  const [rules, setRules] = useState<NetRule[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'events' | 'rules' | 'config'>('overview');

  // Events tab filters
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [sourceIpFilter, setSourceIpFilter] = useState('');
  const [directionFilter, setDirectionFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);

  // Rules tab search
  const [ruleSearch, setRuleSearch] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, rl] = await Promise.all([api.networkGuardStats(), api.networkGuardRules()]);
      setStats(s);
      setRules(rl.rules ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load NetworkGuard data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res: NetEventsResponse = await api.networkGuardEvents(
        eventTypeFilter || undefined,
        sourceIpFilter || undefined,
        directionFilter || undefined,
        eventsPage,
      );
      setEvents(res.events ?? []);
      setEventsTotal(res.total ?? 0);
    } catch {
      setEvents([]);
      setEventsTotal(0);
    } finally {
      setEventsLoading(false);
    }
  }, [eventTypeFilter, sourceIpFilter, directionFilter, eventsPage]);

  useEffect(() => { void loadData(); }, [loadData]);
  useEffect(() => { if (tab === 'events') void loadEvents(); }, [tab, loadEvents]);
  useInterval(loadData, 20000);

  // ─── Derived data ────────────────────────────────────────────────────────────

  const topEventTypes = [...(stats?.event_types ?? [])].sort((a, b) => b.count - a.count).slice(0, 8);
  const maxEvtCount   = topEventTypes[0]?.count ?? 1;

  const protocols = Object.entries(stats?.protocol_breakdown ?? {}).sort((a, b) => b[1] - a[1]);
  const maxProto   = protocols[0]?.[1] ?? 1;

  const filteredRules = rules.filter((r) => {
    if (!ruleSearch) return true;
    const q = ruleSearch.toLowerCase();
    return r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.description.toLowerCase().includes(q) || r.severity.toLowerCase().includes(q);
  });

  // ─── Loading / error states ──────────────────────────────────────────────────

  if (loading) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="card-grid">
          {[0, 1, 2, 3].map(i => <div key={i} className="loading-skeleton" style={{ height: '5rem', borderRadius: '8px' }} />)}
        </div>
        <div className="loading-skeleton" style={{ height: '16rem', borderRadius: '8px', marginTop: '1rem' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>⚠️ {error}</span>
          <button onClick={() => void loadData()} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* ─── Header ──────────────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>🌐 NetworkGuard</h2>
          <p>Network flow monitoring — traffic anomalies, lateral movement, C2 beaconing, and data exfiltration</p>
        </div>
        <button className="btn-secondary" onClick={() => void loadData()} disabled={loading}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {/* ─── Stat strip ──────────────────────────────────────────────────────── */}
      <div className="card-grid">
        <StatCard label="Total Events"   value={(stats?.total_events   ?? 0).toLocaleString()} sub={`Last ${stats?.period ?? '24h'}`} />
        <StatCard label="Threat Events"  value={(stats?.threat_events  ?? 0).toLocaleString()} sub="Tier 2+" color={(stats?.threat_events ?? 0) > 0 ? '#f87171' : undefined} />
        <StatCard label="Unique Sources" value={(stats?.unique_sources  ?? 0).toLocaleString()} sub="Distinct source IPs" />
        <StatCard label="Blocked Flows"  value={(stats?.blocked_flows  ?? 0).toLocaleString()} sub="Policy-blocked" color={(stats?.blocked_flows ?? 0) > 0 ? '#fb923c' : undefined} />
      </div>

      {/* ─── Tabs ─────────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
        {(['overview', 'events', 'rules', 'config'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '0.625rem 1.25rem', background: 'none', border: 'none',
              borderBottom: `2px solid ${tab === t ? '#3b82f6' : 'transparent'}`,
              color: tab === t ? '#60a5fa' : '#64748b',
              fontWeight: 600, fontSize: '0.875rem', cursor: 'pointer',
              transition: 'color 0.12s, border-color 0.12s', marginBottom: '-1px',
            }}
          >
            {t === 'overview' ? 'Overview' : t === 'events' ? 'Events' : t === 'rules' ? 'Detection Rules' : '⚙️ Configuration'}
          </button>
        ))}
      </div>

      {/* ───────────────────────────── Overview tab ──────────────────────────── */}
      {tab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
          {/* Event types */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Top Event Types</div>
            {topEventTypes.length > 0 ? (
              topEventTypes.map((et, i) => (
                <ThreatBar
                  key={et.type}
                  label={et.type}
                  count={et.count}
                  max={maxEvtCount}
                  color={['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#10b981','#6366f1','#14b8a6','#f97316'][i % 8]}
                />
              ))
            ) : (
              <div className="empty-state">No events in the last 24 h</div>
            )}
          </div>

          {/* Protocol breakdown */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Protocol Breakdown</div>
            {protocols.length > 0 ? (
              protocols.map(([proto, count]) => (
                <ThreatBar
                  key={proto}
                  label={proto}
                  count={count}
                  max={maxProto}
                  color={PROTO_COLORS[proto] ?? '#64748b'}
                />
              ))
            ) : (
              <div className="empty-state">No protocol data</div>
            )}
          </div>

          {/* Tier distribution */}
          <div className="card" style={{ gridColumn: 'span 2' }}>
            <div className="section-title" style={{ marginBottom: '1rem' }}>Tier Distribution</div>
            <TierDistribution breakdown={stats?.tier_breakdown ?? {}} />
          </div>

          {/* Active rules summary */}
          <div className="card" style={{ gridColumn: 'span 2' }}>
            <div className="section-title" style={{ marginBottom: '1rem' }}>Active Detection Rules</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '0.75rem' }}>
              {rules.filter(r => r.enabled).map(r => (
                <div key={r.id} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.75rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#f1f5f9' }}>{r.name}</span>
                    <SeverityBadge severity={r.severity} />
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b' }}>{r.id} — {r.tier}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ────────────────────────────── Events tab ───────────────────────────── */}
      {tab === 'events' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Filters */}
          <div className="card" style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: '#64748b', marginBottom: '0.25rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Event Type</label>
              <select
                value={eventTypeFilter}
                onChange={e => { setEventTypeFilter(e.target.value); setEventsPage(1); }}
                style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.625rem', color: '#f1f5f9', fontSize: '0.8125rem' }}
              >
                <option value="">All types</option>
                {(stats?.event_types ?? []).map(et => <option key={et.type} value={et.type}>{et.type.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: '#64748b', marginBottom: '0.25rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Source IP</label>
              <input
                type="text"
                placeholder="e.g. 10.0.1.45"
                value={sourceIpFilter}
                onChange={e => { setSourceIpFilter(e.target.value); setEventsPage(1); }}
                style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.625rem', color: '#f1f5f9', fontSize: '0.8125rem', width: '10rem'  }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: '#64748b', marginBottom: '0.25rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Direction</label>
              <select
                value={directionFilter}
                onChange={e => { setDirectionFilter(e.target.value); setEventsPage(1); }}
                style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.625rem', color: '#f1f5f9', fontSize: '0.8125rem' }}
              >
                <option value="">All</option>
                <option value="inbound">Inbound</option>
                <option value="outbound">Outbound</option>
                <option value="lateral">Lateral</option>
              </select>
            </div>
            <button className="btn-secondary" onClick={() => void loadEvents()}>Apply</button>
            {(eventTypeFilter || sourceIpFilter || directionFilter) && (
              <button
                className="btn-secondary"
                onClick={() => { setEventTypeFilter(''); setSourceIpFilter(''); setDirectionFilter(''); setEventsPage(1); }}
              >
                Clear
              </button>
            )}
          </div>

          {/* Events table */}
          <div className="table-card">
            {eventsLoading ? (
              <div className="loading-skeleton" style={{ height: '12rem', margin: '0.75rem' }} />
            ) : events.length === 0 ? (
              <div className="empty-state">No network events found</div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1e293b' }}>
                    {['Timestamp', 'Source IP', 'Event Type', 'Protocol', 'Dir', 'Port', 'Tier', 'Risk', 'Blocked'].map(h => (
                      <th key={h} style={{ padding: '0.625rem 0.75rem', textAlign: 'left', color: '#475569', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev, i) => {
                    const blocked = evBlocked(ev);
                    return (
                      <tr key={(ev['event_id'] as string | undefined) ?? i} style={{ borderBottom: '1px solid #0f172a' }}>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>{formatTs(ev['timestamp'] as string | undefined)}</td>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#f1f5f9', fontFamily: 'monospace', fontSize: '0.75rem' }}>{evSourceIP(ev)}</td>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#cbd5e1', textTransform: 'capitalize' }}>{evEventType(ev).replace(/_/g, ' ')}</td>
                        <td style={{ padding: '0.5rem 0.75rem' }}>
                          <span style={{ fontWeight: 700, color: PROTO_COLORS[evProtocol(ev)] ?? '#94a3b8', fontSize: '0.75rem' }}>{evProtocol(ev)}</span>
                        </td>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#64748b', fontSize: '0.75rem', textTransform: 'capitalize' }}>{evDirection(ev)}</td>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#64748b', fontFamily: 'monospace', fontSize: '0.75rem' }}>{evDestPort(ev)}</td>
                        <td style={{ padding: '0.5rem 0.75rem' }}><TierBadge tier={(ev['tier'] as number | string | undefined) ?? 0} /></td>
                        <td style={{ padding: '0.5rem 0.75rem', color: '#94a3b8', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                          {ev['risk_score'] !== undefined ? Number(ev['risk_score']).toFixed(1) : '—'}
                        </td>
                        <td style={{ padding: '0.5rem 0.75rem' }}>
                          {blocked
                            ? <span style={{ color: '#dc2626', fontWeight: 700, fontSize: '0.75rem' }}>✕ Blocked</span>
                            : <span style={{ color: '#4ade80', fontSize: '0.75rem' }}>✓ Pass</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          <Pagination
            page={eventsPage}
            pageSize={PAGE_SIZE}
            total={eventsTotal}
            onPageChange={setEventsPage}
          />
        </div>
      )}

      {/* ────────────────────────────── Rules tab ────────────────────────────── */}
      {tab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Search */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <input
              type="text"
              placeholder="Search rules…"
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.875rem', width: '20rem', outline: 'none' }}
            />
            {ruleSearch && (
              <button className="btn-secondary" onClick={() => setRuleSearch('')}>Clear</button>
            )}
            <span style={{ marginLeft: 'auto', fontSize: '0.75rem', color: '#475569' }}>
              {filteredRules.length} of {rules.length} rules
            </span>
          </div>

          {/* Rules table */}
          <div className="table-card">
            {filteredRules.length === 0 ? (
              <div className="empty-state">No matching rules</div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1e293b' }}>
                    {['ID', 'Name', 'Description', 'Severity', 'Tier', 'Responses', 'Status'].map(h => (
                      <th key={h} style={{ padding: '0.625rem 0.75rem', textAlign: 'left', color: '#475569', fontWeight: 600, fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map(r => (
                    <tr key={r.id} style={{ borderBottom: '1px solid #0f172a' }}>
                      <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#60a5fa', fontWeight: 700 }}>{r.id}</td>
                      <td style={{ padding: '0.625rem 0.75rem', color: '#f1f5f9', fontWeight: 600 }}>{r.name}</td>
                      <td style={{ padding: '0.625rem 0.75rem', color: '#94a3b8', maxWidth: '28rem' }}>
                        <span style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{r.description}</span>
                      </td>
                      <td style={{ padding: '0.625rem 0.75rem' }}><SeverityBadge severity={r.severity} /></td>
                      <td style={{ padding: '0.625rem 0.75rem' }}><TierBadge tier={r.tier} /></td>
                      <td style={{ padding: '0.625rem 0.75rem' }}>
                        <div style={{ display: 'flex', gap: '0.375rem', flexWrap: 'wrap' }}>
                          {r.responses.map(resp => (
                            <span key={resp} style={{ fontSize: '0.7rem', padding: '0.125rem 0.375rem', border: '1px solid #334155', borderRadius: '4px', color: '#94a3b8', background: '#1e293b', fontFamily: 'monospace' }}>
                              {resp}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '0.625rem 0.75rem' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.75rem', fontWeight: 700, color: r.enabled ? '#4ade80' : '#475569' }}>
                          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: r.enabled ? '#4ade80' : '#475569', display: 'inline-block' }} />
                          {r.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ────────────────────────── Configuration tab ────────────────────────── */}
      {tab === 'config' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Sensor info */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>🌐 Sensor Configuration</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '1rem' }}>
              {[
                { label: 'Listen Interface', value: 'All interfaces (0.0.0.0)' },
                { label: 'Capture Mode', value: 'Passive (tap/span)' },
                { label: 'Flow Timeout', value: '60 s' },
                { label: 'Max Flows / Window', value: '50,000' },
                { label: 'BPF Filter', value: 'not port 22' },
                { label: 'Sampling Rate', value: '1:1 (100%)' },
              ].map(({ label, value }) => (
                <div key={label} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.75rem 1rem' }}>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: '0.25rem' }}>{label}</div>
                  <div style={{ fontSize: '0.9375rem', color: '#f1f5f9', fontWeight: 600 }}>{value}</div>
                </div>
              ))}
            </div>
            <p style={{ fontSize: '0.75rem', color: '#475569', marginTop: '1rem' }}>
              Sensor configuration is set via environment variables on the networkguard-agent binary. Restart the agent to apply changes.
            </p>
          </div>

          {/* Rule overrides */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>🛡️ Detection Rule Status</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {rules.map(r => (
                <div key={r.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.625rem 0.875rem', background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: r.enabled ? '#4ade80' : '#475569', flexShrink: 0 }} />
                    <div>
                      <span style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f1f5f9' }}>{r.name}</span>
                      <span style={{ marginLeft: '0.625rem', fontSize: '0.7rem', color: '#475569', fontFamily: 'monospace' }}>{r.id}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <SeverityBadge severity={r.severity} />
                    <TierBadge tier={r.tier} />
                    <span style={{ fontSize: '0.75rem', color: r.enabled ? '#4ade80' : '#475569', fontWeight: 700 }}>
                      {r.enabled ? 'Active' : 'Disabled'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Allowlists info */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '0.75rem' }}>📋 Allowlist Management</div>
            <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: '0.75rem' }}>
              Allowlists for approved remote-access sources, trusted external IPs, and internal subnets are managed via the policies configuration.
            </p>
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              {['Remote access IPs', 'Trusted external hosts', 'Internal subnet ranges', 'Approved countries'].map(label => (
                <span key={label} style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '4px', color: '#94a3b8' }}>{label}</span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
