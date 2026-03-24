import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { HostStatsResponse, HostRule, Event, HostGuardConfigResponse, HostSensorConfig, RuleOverride, ConfiguredHostRule } from '../api';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';
import { useToast } from '../contexts/ToastContext';

// ─── Constants ────────────────────────────────────────────────────────────────

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

// ─── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const bg    = SEVERITY_BG[severity]    ?? SEVERITY_BG.info;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {severity}
    </span>
  );
}

// ─── Tier badge ────────────────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: number | string }) {
  const t = typeof tier === 'number' ? `T${tier}` : String(tier);
  const color = TIER_COLORS[t] ?? TIER_COLORS.T0;
  const bg    = TIER_BG[t]    ?? TIER_BG.T0;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
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

// ─── Threat bar ────────────────────────────────────────────────────────────────

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

// ─── Tier distribution bar ────────────────────────────────────────────────────

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

// ─── Event type label helper ──────────────────────────────────────────────────

function eventTypeLabel(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const et = meta['event_type'];
    if (typeof et === 'string') return et;
  }
  return (ev['type'] as string | undefined) ?? '—';
}

function processName(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const pn = meta['process_name'];
    if (typeof pn === 'string') return pn;
  }
  return '—';
}

function processPid(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const pid = meta['pid'];
    if (pid !== undefined) return String(pid);
  }
  return '—';
}

function hostname(ev: Event): string {
  return (ev['source'] as string | undefined) ?? '—';
}

function indicators(ev: Event): string[] {
  const raw = ev['indicators'];
  if (Array.isArray(raw)) return raw as string[];
  return [];
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function HostGuard() {
  const [stats, setStats] = useState<HostStatsResponse | null>(null);
  const [rules, setRules] = useState<HostRule[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'events' | 'rules' | 'config'>('overview');

  // Config tab state
  const [configData, setConfigData] = useState<HostGuardConfigResponse | null>(null);
  const [configLoading, setConfigLoading] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [sensorForm, setSensorForm] = useState<HostSensorConfig>({ scan_interval_secs: 30, cpu_alert_threshold_pct: 85, mem_alert_threshold_mb: 512 });
  const [sensorEditing, setSensorEditing] = useState(false);
  const [savingSensor, setSavingSensor] = useState(false);
  const [ruleEditTarget, setRuleEditTarget] = useState<ConfiguredHostRule | null>(null);
  const [ruleEditForm, setRuleEditForm] = useState<{ enabled: boolean; severity: string; tier: string }>({ enabled: true, severity: 'medium', tier: 'T2' });
  const [savingRuleId, setSavingRuleId] = useState<string | null>(null);

  // Events tab filters
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);
  const PAGE_SIZE = 25;

  // Rules tab search
  const [ruleSearch, setRuleSearch] = useState('');

  const { addToast } = useToast();

  const loadConfig = useCallback(async () => {
    setConfigLoading(true);
    setConfigError(null);
    try {
      const cfg = await api.configHostGuard();
      setConfigData(cfg);
      setSensorForm(cfg.sensor_config);
    } catch (e) {
      setConfigError(e instanceof Error ? e.message : 'Failed to load HostGuard config');
    } finally {
      setConfigLoading(false);
    }
  }, []);

  async function saveSensorConfig() {
    setSavingSensor(true);
    try {
      await api.updateHostGuardSensor(sensorForm);
      setConfigData(prev => prev ? { ...prev, sensor_config: sensorForm } : prev);
      setSensorEditing(false);
      addToast('Sensor configuration saved', 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to save sensor config', 'error');
    } finally {
      setSavingSensor(false);
    }
  }

  function openRuleEdit(rule: ConfiguredHostRule) {
    setRuleEditTarget(rule);
    setRuleEditForm({
      enabled: rule.enabled,
      severity: rule.severity,
      tier: typeof rule.tier === 'number' ? `T${rule.tier}` : String(rule.tier),
    });
  }

  async function saveRuleOverride() {
    if (!ruleEditTarget) return;
    setSavingRuleId(ruleEditTarget.id);
    try {
      const override: RuleOverride = { enabled: ruleEditForm.enabled, severity: ruleEditForm.severity, tier: ruleEditForm.tier };
      await api.updateHostGuardRule(ruleEditTarget.id, override);
      setConfigData(prev => {
        if (!prev) return prev;
        return {
          ...prev,
          rules: prev.rules.map(r =>
            r.id === ruleEditTarget.id
              ? { ...r, enabled: ruleEditForm.enabled, severity: ruleEditForm.severity, tier: ruleEditForm.tier }
              : r
          ),
        };
      });
      addToast(`Rule "${ruleEditTarget.name}" updated`, 'success');
      setRuleEditTarget(null);
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to update rule', 'error');
    } finally {
      setSavingRuleId(null);
    }
  }

  async function toggleRuleEnabled(rule: ConfiguredHostRule) {
    setSavingRuleId(rule.id);
    try {
      const tier = typeof rule.tier === 'number' ? `T${rule.tier}` : String(rule.tier);
      const override: RuleOverride = { enabled: !rule.enabled, severity: rule.severity, tier };
      await api.updateHostGuardRule(rule.id, override);
      setConfigData(prev => {
        if (!prev) return prev;
        return { ...prev, rules: prev.rules.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r) };
      });
      addToast(`Rule "${rule.name}" ${!rule.enabled ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to toggle rule', 'error');
    } finally {
      setSavingRuleId(null);
    }
  }

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, rl] = await Promise.all([api.hostGuardStats(), api.hostGuardRules()]);
      setStats(s);
      setRules(rl.rules ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load HostGuard data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res = await api.hostGuardEvents(
        eventTypeFilter || undefined,
        hostnameFilter || undefined,
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
  }, [eventTypeFilter, hostnameFilter, eventsPage]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  useEffect(() => {
    if (tab === 'events') void loadEvents();
  }, [tab, loadEvents]);

  useEffect(() => {
    if (tab === 'config') void loadConfig();
  }, [tab, loadConfig]);

  useInterval(loadData, 20000);

  // ─── Filtered rules ─────────────────────────────────────────────────────────
  const filteredRules = rules.filter((r) => {
    if (!ruleSearch) return true;
    const q = ruleSearch.toLowerCase();
    return (
      r.name.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q)
    );
  });

  // ─── Top event types ────────────────────────────────────────────────────────
  const topEventTypes = [...(stats?.event_types ?? [])]
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // ─── Page count ─────────────────────────────────────────────────────────────
  // totalPages computed by Pagination component

  // ─── Render loading ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="card-grid">
          {[0, 1, 2, 3].map(i => (
            <div key={i} className="loading-skeleton" style={{ height: '5rem', borderRadius: '8px' }} />
          ))}
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
      {/* ─── Header ─────────────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>🖥️ HostGuard</h2>
          <p>Host-level threat detection — processes, network, persistence, and privilege escalation</p>
        </div>
        <button className="btn-secondary" onClick={() => void loadData()} disabled={loading}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {/* ─── Stat strip ─────────────────────────────────────────────────────── */}
      <div className="card-grid">
        <StatCard label="Total Events" value={(stats?.total_events ?? 0).toLocaleString()} sub={`Last ${stats?.period ?? '24h'}`} />
        <StatCard label="Threat Events" value={(stats?.threat_events ?? 0).toLocaleString()} sub="Tier 2+" color={(stats?.threat_events ?? 0) > 0 ? '#f87171' : undefined} />
        <StatCard label="Unique Hosts" value={stats?.unique_hosts ?? 0} sub="Monitored endpoints" />
        <StatCard label="Active Rules" value={stats?.active_rules ?? 0} sub={`of ${rules.length} total`} />
      </div>

      {/* ─── Tabs ────────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
        {(['overview', 'events', 'rules', 'config'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '0.625rem 1.25rem',
              background: 'none',
              border: 'none',
              borderBottom: `2px solid ${tab === t ? '#3b82f6' : 'transparent'}`,
              color: tab === t ? '#60a5fa' : '#64748b',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              transition: 'color 0.12s, border-color 0.12s',
              marginBottom: '-1px',
            }}
          >
            {t === 'overview' ? 'Overview' : t === 'events' ? 'Events' : t === 'rules' ? 'Detection Rules' : '⚙️ Configuration'}
          </button>
        ))}
      </div>

      {/* ─── Overview tab ────────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Top Event Types</div>
            {topEventTypes.length > 0 ? (
              topEventTypes.map((item, idx) => (
                <ThreatBar
                  key={item.type}
                  label={item.type}
                  count={item.count}
                  max={topEventTypes[0]?.count ?? 1}
                  color={['#3b82f6','#06b6d4','#ea580c','#dc2626','#7c3aed','#d97706','#ec4899','#14b8a6'][idx % 8]}
                />
              ))
            ) : (
              <div className="empty-state">No event data</div>
            )}
          </div>

          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Tier Distribution</div>
            {stats?.tier_breakdown ? (
              <TierDistribution breakdown={stats.tier_breakdown} />
            ) : (
              <div className="empty-state">No tier data</div>
            )}
          </div>

          <div className="card" style={{ gridColumn: 'span 2' }}>
            <div className="section-title" style={{ marginBottom: '1rem' }}>Detection Coverage</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '0.75rem' }}>
              {rules.map(rule => (
                <div key={rule.id} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', borderLeft: `3px solid ${SEVERITY_COLORS[rule.severity] ?? '#475569'}` }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
                    <TierBadge tier={rule.tier} />
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: rule.enabled ? '#4ade80' : '#334155', display: 'inline-block' }} />
                  </div>
                  <p style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0', marginTop: '0.5rem', lineHeight: 1.3 }}>{rule.name}</p>
                  <div style={{ marginTop: '0.375rem' }}>
                    <SeverityBadge severity={rule.severity} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ─── Events tab ──────────────────────────────────────────────────────── */}
      {tab === 'events' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Filter by event type…"
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setEventsPage(1); }}
            />
            <input
              type="text"
              placeholder="Filter by hostname…"
              value={hostnameFilter}
              onChange={(e) => { setHostnameFilter(e.target.value); setEventsPage(1); }}
            />
            <button className="btn-secondary" onClick={() => { setEventTypeFilter(''); setHostnameFilter(''); setEventsPage(1); }}>
              Clear
            </button>
          </div>

          <div className="table-card">
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155' }}>
                    {['Time', 'Hostname', 'Event Type', 'Process', 'PID', 'Tier', 'Indicators'].map(h => (
                      <th key={h} style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {eventsLoading ? (
                    <tr><td colSpan={7} style={{ padding: '3rem', textAlign: 'center' }}>
                      <div style={{ width: '24px', height: '24px', border: '2px solid #3b82f6', borderTopColor: 'transparent', borderRadius: '50%', margin: '0 auto', animation: 'spin 0.8s linear infinite' }} />
                    </td></tr>
                  ) : events.length === 0 ? (
                    <tr><td colSpan={7} className="empty-state">No host events found</td></tr>
                  ) : events.map((ev, idx) => {
                    const ind = indicators(ev);
                    const tier = typeof ev['tier'] === 'number' ? ev['tier'] as number : 0;
                    return (
                      <tr key={(ev['id'] as string | undefined) ?? idx} style={{ borderBottom: '1px solid #1e293b' }}
                        onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                          {new Date((ev['timestamp'] as string | undefined) ?? '').toLocaleString()}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f1f5f9' }}>{hostname(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', background: '#0f172a', color: '#94a3b8', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>
                            {eventTypeLabel(ev)}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>{processName(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b' }}>{processPid(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem' }}><TierBadge tier={tier} /></td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {ind.slice(0, 3).map(tag => (
                              <span key={tag} style={{ fontSize: '0.7rem', background: '#1c0a0a', color: '#fca5a5', border: '1px solid #7f1d1d', borderRadius: '4px', padding: '0.125rem 0.375rem' }}>
                                {tag.replace(/_/g, ' ')}
                              </span>
                            ))}
                            {ind.length > 3 && <span style={{ fontSize: '0.75rem', color: '#64748b' }}>+{ind.length - 3} more</span>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {eventsTotal > PAGE_SIZE && (
              <div style={{ padding: '0.75rem 1.25rem', borderTop: '1px solid #334155' }}>
                <Pagination page={eventsPage} pageSize={PAGE_SIZE} total={eventsTotal} onPageChange={setEventsPage} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── Rules tab ───────────────────────────────────────────────────────── */}
      {tab === 'rules' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Search rules by name, ID, or severity…"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              style={{ width: '100%', maxWidth: 'none' }}
            />
            {ruleSearch && (
              <button className="btn-secondary" onClick={() => setRuleSearch('')}>Clear</button>
            )}
          </div>

          {filteredRules.length === 0 ? (
            <div className="card empty-state">No rules match your search</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {filteredRules.map(rule => (
                <div key={rule.id} className="card" style={{ borderLeft: `3px solid ${SEVERITY_COLORS[rule.severity] ?? '#475569'}` }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem', flexWrap: 'wrap' }}>
                        <span style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9' }}>{rule.name}</span>
                        <code style={{ fontSize: '0.7rem', color: '#475569', background: '#0f172a', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>{rule.id}</code>
                      </div>
                      <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.625rem' }}>{rule.description}</p>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                        {rule.responses.map(r => (
                          <span key={r} style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '4px', background: '#1e3a5f', color: '#93c5fd', border: '1px solid #1d4ed8' }}>
                            {r.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem', flexShrink: 0 }}>
                      <SeverityBadge severity={rule.severity} />
                      <TierBadge tier={rule.tier} />
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: rule.enabled ? '#4ade80' : '#475569' }}>
                        {rule.enabled ? '● Enabled' : '○ Disabled'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ─── Config tab ──────────────────────────────────────────────────────── */}
      {tab === 'config' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {configLoading && (
            <>
              <div className="loading-skeleton" style={{ height: '8rem', borderRadius: '8px' }} />
              <div className="loading-skeleton" style={{ height: '16rem', borderRadius: '8px' }} />
            </>
          )}
          {configError && (
            <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>⚠️ {configError}</span>
              <button onClick={() => void loadConfig()} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}>Retry</button>
            </div>
          )}
          {!configLoading && !configError && configData && (
            <>
              {/* ── Sensor Settings ── */}
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <div className="section-title">🔧 Sensor Settings</div>
                  {!sensorEditing ? (
                    <button className="btn-secondary" onClick={() => setSensorEditing(true)}>Edit</button>
                  ) : (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn-secondary" onClick={() => { setSensorEditing(false); setSensorForm(configData.sensor_config); }}>Cancel</button>
                      <button
                        onClick={() => void saveSensorConfig()}
                        disabled={savingSensor}
                        style={{ padding: '0.375rem 1rem', background: '#1d4ed8', border: '1px solid #2563eb', borderRadius: '6px', color: '#fff', fontWeight: 600, cursor: savingSensor ? 'not-allowed' : 'pointer', opacity: savingSensor ? 0.7 : 1, fontSize: '0.875rem' }}
                      >
                        {savingSensor ? 'Saving…' : 'Save'}
                      </button>
                    </div>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '1.25rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Scan Interval (seconds)</label>
                    {sensorEditing ? (
                      <input
                        type="number" min={5} max={3600}
                        value={sensorForm.scan_interval_secs}
                        onChange={e => setSensorForm(f => ({ ...f, scan_interval_secs: Number(e.target.value) }))}
                        style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem' }}
                      />
                    ) : (
                      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#60a5fa' }}>{configData.sensor_config.scan_interval_secs}s</div>
                    )}
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>CPU Alert Threshold (%)</label>
                    {sensorEditing ? (
                      <input
                        type="number" min={1} max={100}
                        value={sensorForm.cpu_alert_threshold_pct}
                        onChange={e => setSensorForm(f => ({ ...f, cpu_alert_threshold_pct: Number(e.target.value) }))}
                        style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem' }}
                      />
                    ) : (
                      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f59e0b' }}>{configData.sensor_config.cpu_alert_threshold_pct}%</div>
                    )}
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Memory Alert Threshold (MB)</label>
                    {sensorEditing ? (
                      <input
                        type="number" min={64} max={65536}
                        value={sensorForm.mem_alert_threshold_mb}
                        onChange={e => setSensorForm(f => ({ ...f, mem_alert_threshold_mb: Number(e.target.value) }))}
                        style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem' }}
                      />
                    ) : (
                      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#4ade80' }}>{configData.sensor_config.mem_alert_threshold_mb} MB</div>
                    )}
                  </div>
                </div>
              </div>

              {/* ── Rule Overrides ── */}
              <div className="card">
                <div className="section-title" style={{ marginBottom: '1rem' }}>🛡️ Detection Rule Overrides</div>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #334155' }}>
                        {['Rule', 'ID', 'Severity', 'Tier', 'Status', 'Actions'].map(h => (
                          <th key={h} style={{ padding: '0.625rem 0.75rem', textAlign: 'left', fontSize: '0.7rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {configData.rules.map(rule => (
                        <tr key={rule.id} style={{ borderBottom: '1px solid #1e293b' }}
                          onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                          <td style={{ padding: '0.75rem 0.75rem', fontWeight: 600, color: '#f1f5f9', maxWidth: '200px' }}>
                            <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={rule.description}>{rule.name}</div>
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem' }}>
                            <code style={{ fontSize: '0.7rem', color: '#475569', background: '#0f172a', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>{rule.id}</code>
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem' }}><SeverityBadge severity={rule.severity} /></td>
                          <td style={{ padding: '0.75rem 0.75rem' }}><TierBadge tier={rule.tier} /></td>
                          <td style={{ padding: '0.75rem 0.75rem' }}>
                            <button
                              onClick={() => void toggleRuleEnabled(rule)}
                              disabled={savingRuleId === rule.id}
                              style={{ background: 'none', border: 'none', cursor: savingRuleId === rule.id ? 'not-allowed' : 'pointer', fontSize: '0.8125rem', fontWeight: 600, color: rule.enabled ? '#4ade80' : '#475569', padding: 0 }}
                              title={rule.enabled ? 'Click to disable' : 'Click to enable'}
                            >
                              {savingRuleId === rule.id ? '…' : rule.enabled ? '● Enabled' : '○ Disabled'}
                            </button>
                          </td>
                          <td style={{ padding: '0.75rem 0.75rem' }}>
                            <button
                              className="btn-secondary"
                              onClick={() => openRuleEdit(rule)}
                              disabled={savingRuleId === rule.id}
                              style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem' }}
                            >
                              Edit
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {/* ── Rule edit modal ── */}
          {ruleEditTarget && (
            <div
              style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
              onClick={e => { if (e.target === e.currentTarget) setRuleEditTarget(null); }}
            >
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', padding: '1.5rem', width: '100%', maxWidth: '440px', boxShadow: '0 25px 50px rgba(0,0,0,0.5)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
                  <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: '#f1f5f9' }}>Edit Rule Override</h3>
                  <button onClick={() => setRuleEditTarget(null)} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '1.25rem', lineHeight: 1 }}>✕</button>
                </div>
                <div style={{ marginBottom: '1.25rem', padding: '0.75rem', background: '#0f172a', borderRadius: '8px', border: '1px solid #334155' }}>
                  <p style={{ margin: 0, fontWeight: 700, color: '#e2e8f0' }}>{ruleEditTarget.name}</p>
                  <p style={{ margin: '0.25rem 0 0', fontSize: '0.8125rem', color: '#64748b' }}>{ruleEditTarget.description}</p>
                  <code style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.375rem', display: 'inline-block' }}>{ruleEditTarget.id}</code>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Status</label>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => setRuleEditForm(f => ({ ...f, enabled: true }))}
                        style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', border: ruleEditForm.enabled ? '2px solid #22c55e' : '1px solid #334155', background: ruleEditForm.enabled ? '#14532d' : '#0f172a', color: ruleEditForm.enabled ? '#4ade80' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.875rem' }}
                      >
                        ● Enabled
                      </button>
                      <button
                        onClick={() => setRuleEditForm(f => ({ ...f, enabled: false }))}
                        style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', border: !ruleEditForm.enabled ? '2px solid #475569' : '1px solid #334155', background: !ruleEditForm.enabled ? '#1e293b' : '#0f172a', color: !ruleEditForm.enabled ? '#94a3b8' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.875rem' }}
                      >
                        ○ Disabled
                      </button>
                    </div>
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Severity</label>
                    <select
                      value={ruleEditForm.severity}
                      onChange={e => setRuleEditForm(f => ({ ...f, severity: e.target.value }))}
                      style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem', cursor: 'pointer' }}
                    >
                      {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                        <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Tier</label>
                    <select
                      value={ruleEditForm.tier}
                      onChange={e => setRuleEditForm(f => ({ ...f, tier: e.target.value }))}
                      style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem', cursor: 'pointer' }}
                    >
                      {['T1', 'T2', 'T3', 'T4'].map(t => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', marginTop: '1.5rem' }}>
                  <button className="btn-secondary" onClick={() => setRuleEditTarget(null)} style={{ flex: 1 }}>Cancel</button>
                  <button
                    onClick={() => void saveRuleOverride()}
                    disabled={savingRuleId === ruleEditTarget.id}
                    style={{ flex: 1, padding: '0.5rem', background: '#1d4ed8', border: '1px solid #2563eb', borderRadius: '6px', color: '#fff', fontWeight: 600, cursor: savingRuleId === ruleEditTarget.id ? 'not-allowed' : 'pointer', opacity: savingRuleId === ruleEditTarget.id ? 0.7 : 1, fontSize: '0.875rem' }}
                  >
                    {savingRuleId === ruleEditTarget.id ? 'Saving…' : 'Save Changes'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}



