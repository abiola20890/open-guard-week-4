import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { HostStatsResponse, HostRule, Event } from '../api';

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high:     'bg-orange-100 text-orange-800 border-orange-200',
    medium:   'bg-yellow-100 text-yellow-800 border-yellow-200',
    low:      'bg-blue-100 text-blue-800 border-blue-200',
    info:     'bg-gray-100 text-gray-700 border-gray-200',
  };
  const cls = map[severity] ?? map.info;
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

// ─── Tier badge ───────────────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: number | string }) {
  const t = typeof tier === 'number' ? `T${tier}` : String(tier);
  const map: Record<string, string> = {
    T0: 'bg-gray-100 text-gray-600 border-gray-200',
    T1: 'bg-blue-100 text-blue-700 border-blue-200',
    T2: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    T3: 'bg-orange-100 text-orange-800 border-orange-200',
    T4: 'bg-red-100 text-red-800 border-red-200',
  };
  const cls = map[t] ?? 'bg-gray-100 text-gray-600 border-gray-200';
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {t}
    </span>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: number | string;
  sub?: string;
  accent?: string;
}) {
  const border = accent ?? 'border-l-blue-400';
  return (
    <div className={`bg-white rounded-lg shadow-sm border border-gray-200 border-l-4 ${border} p-5`}>
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

// ─── Bar chart ────────────────────────────────────────────────────────────────

function BarChart({ items }: { items: { type: string; count: number }[] }) {
  const max = Math.max(...items.map((i) => i.count), 1);
  const palette = [
    'bg-blue-500',
    'bg-teal-500',
    'bg-orange-500',
    'bg-red-500',
    'bg-purple-500',
    'bg-yellow-500',
    'bg-pink-500',
    'bg-indigo-500',
  ];
  return (
    <div className="space-y-2">
      {items.map((item, idx) => (
        <div key={item.type} className="flex items-center gap-3">
          <span className="w-48 text-xs text-gray-600 truncate capitalize">
            {item.type.replace(/_/g, ' ')}
          </span>
          <div className="flex-1 h-4 bg-gray-100 rounded overflow-hidden">
            <div
              className={`h-full rounded ${palette[idx % palette.length]}`}
              style={{ width: `${(item.count / max) * 100}%` }}
            />
          </div>
          <span className="w-8 text-xs text-gray-500 text-right">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Tier distribution bar ────────────────────────────────────────────────────

function TierDistribution({ breakdown }: { breakdown: Record<string, number> }) {
  const tiers = ['T0', 'T1', 'T2', 'T3', 'T4'];
  const total = tiers.reduce((s, t) => s + (breakdown[t] ?? 0), 0) || 1;
  const colours: Record<string, string> = {
    T0: 'bg-gray-300',
    T1: 'bg-blue-400',
    T2: 'bg-yellow-400',
    T3: 'bg-orange-500',
    T4: 'bg-red-600',
  };
  return (
    <div>
      <div className="flex rounded-full overflow-hidden h-4 mb-3">
        {tiers.map((t) => {
          const pct = ((breakdown[t] ?? 0) / total) * 100;
          return pct > 0 ? (
            <div key={t} className={`${colours[t]} h-full`} style={{ width: `${pct}%` }} title={`${t}: ${breakdown[t] ?? 0}`} />
          ) : null;
        })}
      </div>
      <div className="flex gap-4 flex-wrap">
        {tiers.map((t) => (
          <div key={t} className="flex items-center gap-1.5">
            <span className={`w-2.5 h-2.5 rounded-full ${colours[t]}`} />
            <span className="text-xs text-gray-500">
              {t}: <strong>{breakdown[t] ?? 0}</strong>
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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'events' | 'rules'>('overview');

  // Events tab filters
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);
  const PAGE_SIZE = 25;

  // Rules tab search
  const [ruleSearch, setRuleSearch] = useState('');

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
    }
  }, [eventTypeFilter, hostnameFilter, eventsPage]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  useEffect(() => {
    if (tab === 'events') void loadEvents();
  }, [tab, loadEvents]);

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
  const totalPages = Math.max(1, Math.ceil(eventsTotal / PAGE_SIZE));

  // ─── Render loading ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="p-8">
        <div className="animate-pulse space-y-4 max-w-6xl mx-auto">
          <div className="h-8 bg-gray-200 rounded w-1/3" />
          <div className="grid grid-cols-4 gap-4">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-200 rounded-lg" />
            ))}
          </div>
          <div className="h-64 bg-gray-200 rounded-lg" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 max-w-6xl mx-auto">
        <div className="bg-red-50 border border-red-200 text-red-800 rounded-lg p-4">
          <strong>Error:</strong> {error}
          <button
            onClick={() => void loadData()}
            className="ml-4 underline text-red-700 hover:text-red-900"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* ─── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">🖥️ HostGuard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Host-level threat detection — processes, network, persistence, and privilege escalation
          </p>
        </div>
        <button
          onClick={() => void loadData()}
          className="px-4 py-2 rounded-lg bg-blue-50 text-blue-700 border border-blue-200 text-sm font-semibold hover:bg-blue-100 transition-colors"
        >
          ↻ Refresh
        </button>
      </div>

      {/* ─── Stat strip ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          label="Total Events"
          value={(stats?.total_events ?? 0).toLocaleString()}
          sub={`Last ${stats?.period ?? '24h'}`}
          accent="border-l-blue-400"
        />
        <StatCard
          label="Threat Events"
          value={(stats?.threat_events ?? 0).toLocaleString()}
          sub="Tier 2+"
          accent="border-l-red-400"
        />
        <StatCard
          label="Unique Hosts"
          value={stats?.unique_hosts ?? 0}
          sub="Monitored endpoints"
          accent="border-l-teal-400"
        />
        <StatCard
          label="Active Rules"
          value={stats?.active_rules ?? 0}
          sub={`of ${rules.length} total`}
          accent="border-l-purple-400"
        />
      </div>

      {/* ─── Tabs ────────────────────────────────────────────────────────────── */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6">
          {(['overview', 'events', 'rules'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`pb-3 text-sm font-semibold capitalize border-b-2 transition-colors ${
                tab === t
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t === 'overview' ? 'Overview' : t === 'events' ? 'Events' : 'Detection Rules'}
            </button>
          ))}
        </nav>
      </div>

      {/* ─── Overview tab ────────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Event type breakdown */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-4">
              Top Event Types
            </h2>
            {topEventTypes.length > 0 ? (
              <BarChart items={topEventTypes} />
            ) : (
              <p className="text-sm text-gray-400 text-center py-8">No event data</p>
            )}
          </div>

          {/* Threat tier distribution */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-4">
              Tier Distribution
            </h2>
            {stats?.tier_breakdown ? (
              <TierDistribution breakdown={stats.tier_breakdown} />
            ) : (
              <p className="text-sm text-gray-400 text-center py-8">No tier data</p>
            )}
          </div>

          {/* Rule summary */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 lg:col-span-2">
            <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-4">
              Detection Coverage
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className="rounded-lg border border-gray-100 bg-gray-50 p-3 hover:bg-white hover:border-gray-200 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <TierBadge tier={rule.tier} />
                    {rule.enabled ? (
                      <span className="w-2 h-2 rounded-full bg-green-400" title="Enabled" />
                    ) : (
                      <span className="w-2 h-2 rounded-full bg-gray-300" title="Disabled" />
                    )}
                  </div>
                  <p className="text-xs font-semibold text-gray-800 mt-2 leading-tight">{rule.name}</p>
                  <div className="mt-1">
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
        <div className="bg-white rounded-xl shadow-sm border border-gray-200">
          {/* Filter bar */}
          <div className="p-4 border-b border-gray-100 flex flex-wrap gap-3">
            <input
              type="text"
              placeholder="Filter by event type…"
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setEventsPage(1); }}
              className="flex-1 min-w-40 px-3 py-2 rounded-lg border border-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-200"
            />
            <input
              type="text"
              placeholder="Filter by hostname…"
              value={hostnameFilter}
              onChange={(e) => { setHostnameFilter(e.target.value); setEventsPage(1); }}
              className="flex-1 min-w-40 px-3 py-2 rounded-lg border border-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-200"
            />
            <button
              onClick={() => { setEventTypeFilter(''); setHostnameFilter(''); setEventsPage(1); }}
              className="px-3 py-2 rounded-lg border border-gray-200 text-sm text-gray-500 hover:bg-gray-50"
            >
              Clear
            </button>
            <button
              onClick={() => void loadEvents()}
              className="px-3 py-2 rounded-lg bg-blue-50 text-blue-700 border border-blue-200 text-sm font-semibold hover:bg-blue-100"
            >
              Search
            </button>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-xs text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3 text-left">Time</th>
                  <th className="px-4 py-3 text-left">Hostname</th>
                  <th className="px-4 py-3 text-left">Event Type</th>
                  <th className="px-4 py-3 text-left">Process</th>
                  <th className="px-4 py-3 text-left">PID</th>
                  <th className="px-4 py-3 text-left">Tier</th>
                  <th className="px-4 py-3 text-left">Indicators</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-gray-400">
                      No host events found
                    </td>
                  </tr>
                ) : (
                  events.map((ev, idx) => {
                    const ind = indicators(ev);
                    const tier = typeof ev['tier'] === 'number' ? ev['tier'] as number : 0;
                    return (
                      <tr
                        key={(ev['id'] as string | undefined) ?? idx}
                        className="border-b border-gray-50 hover:bg-blue-50/30 transition-colors"
                      >
                        <td className="px-4 py-3 text-gray-500 font-mono text-xs whitespace-nowrap">
                          {new Date((ev['timestamp'] as string | undefined) ?? '').toLocaleString()}
                        </td>
                        <td className="px-4 py-3 font-medium text-gray-800">{hostname(ev)}</td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs bg-gray-100 text-gray-700 px-1.5 py-0.5 rounded">
                            {eventTypeLabel(ev)}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">{processName(ev)}</td>
                        <td className="px-4 py-3 text-gray-500 font-mono text-xs">{processPid(ev)}</td>
                        <td className="px-4 py-3">
                          <TierBadge tier={tier} />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {ind.slice(0, 3).map((ind) => (
                              <span
                                key={ind}
                                className="text-xs bg-red-50 text-red-700 border border-red-100 rounded px-1.5 py-0.5"
                              >
                                {ind.replace(/_/g, ' ')}
                              </span>
                            ))}
                            {ind.length > 3 && (
                              <span className="text-xs text-gray-400">+{ind.length - 3} more</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between text-sm text-gray-500">
            <span>
              {eventsTotal > 0
                ? `Showing ${(eventsPage - 1) * PAGE_SIZE + 1}–${Math.min(eventsPage * PAGE_SIZE, eventsTotal)} of ${eventsTotal}`
                : 'No results'}
            </span>
            <div className="flex gap-2">
              <button
                disabled={eventsPage <= 1}
                onClick={() => setEventsPage((p) => p - 1)}
                className="px-3 py-1 rounded border border-gray-200 disabled:opacity-40 hover:bg-gray-50"
              >
                ← Prev
              </button>
              <span className="px-3 py-1 text-gray-600">
                Page {eventsPage} / {totalPages}
              </span>
              <button
                disabled={eventsPage >= totalPages}
                onClick={() => setEventsPage((p) => p + 1)}
                className="px-3 py-1 rounded border border-gray-200 disabled:opacity-40 hover:bg-gray-50"
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Rules tab ───────────────────────────────────────────────────────── */}
      {tab === 'rules' && (
        <div className="space-y-4">
          {/* Search */}
          <div className="flex gap-3">
            <input
              type="text"
              placeholder="Search rules by name, ID, or severity…"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              className="flex-1 px-3 py-2 rounded-lg border border-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-200"
            />
            {ruleSearch && (
              <button
                onClick={() => setRuleSearch('')}
                className="px-3 py-2 rounded-lg border border-gray-200 text-sm text-gray-500 hover:bg-gray-50"
              >
                Clear
              </button>
            )}
          </div>

          {/* Rule cards */}
          {filteredRules.length === 0 ? (
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center text-gray-400">
              No rules match your search
            </div>
          ) : (
            filteredRules.map((rule) => (
              <div
                key={rule.id}
                className="bg-white rounded-xl shadow-sm border border-gray-200 border-l-4 border-l-blue-400 p-5"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <h3 className="text-base font-semibold text-gray-900">{rule.name}</h3>
                      <span className="font-mono text-xs text-gray-400">{rule.id}</span>
                    </div>
                    <p className="text-sm text-gray-600">{rule.description}</p>

                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {rule.responses.map((r) => (
                        <span
                          key={r}
                          className="inline-block text-xs bg-gray-100 text-gray-600 border border-gray-200 rounded px-2 py-0.5 font-medium"
                        >
                          {r}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <SeverityBadge severity={rule.severity} />
                    <TierBadge tier={rule.tier} />
                    {rule.enabled ? (
                      <span className="text-xs text-green-600 font-semibold">● Enabled</span>
                    ) : (
                      <span className="text-xs text-gray-400 font-semibold">○ Disabled</span>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
