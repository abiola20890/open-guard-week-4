import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type {
  ModelGuardStatsResponse,
  ModelCallEntry,
  ProviderHealthEntry,
  GuardrailConfig,
  KvStat,
} from '../api';
import { useToast } from '../contexts/ToastContext';

// ─── Shared UI atoms ──────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
  accent = 'border-l-blue-400',
}: {
  label: string;
  value: number | string;
  sub?: string;
  accent?: string;
}) {
  return (
    <div
      className={`bg-white rounded-lg shadow-sm border border-gray-200 border-l-4 ${accent} p-5`}
    >
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-green-100 text-green-800 border-green-200',
  };
  const cls = map[level] ?? 'bg-gray-100 text-gray-600 border-gray-200';
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${cls}`}
    >
      {level}
    </span>
  );
}

function StrategyBadge({ strategy }: { strategy: string }) {
  const map: Record<string, string> = {
    single: 'bg-blue-50 text-blue-700 border-blue-100',
    fallback: 'bg-yellow-50 text-yellow-700 border-yellow-100',
    quorum: 'bg-purple-50 text-purple-700 border-purple-100',
  };
  const cls = map[strategy] ?? 'bg-gray-100 text-gray-600 border-gray-200';
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>
      {strategy}
    </span>
  );
}

function BarChart({ items }: { items: KvStat[] }) {
  const max = Math.max(...items.map((i) => i.count), 1);
  const palette = [
    'bg-blue-500',
    'bg-purple-500',
    'bg-green-500',
    'bg-orange-500',
    'bg-pink-500',
    'bg-teal-500',
  ];
  return (
    <div className="space-y-2">
      {items.map((item, idx) => (
        <div key={item.label} className="flex items-center gap-3">
          <span className="w-36 text-xs text-gray-600 truncate capitalize">
            {item.label.replace(/-/g, ' ')}
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

// ─── Provider health panel ────────────────────────────────────────────────────

function ProviderHealthPanel({ providers }: { providers: ProviderHealthEntry[] }) {
  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-100">
        <h2 className="text-base font-semibold text-gray-900">Provider Health</h2>
      </div>
      <div className="divide-y divide-gray-100">
        {providers.map((p) => (
          <div key={p.id} className="px-5 py-4 flex items-center gap-4">
            <div
              className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${p.healthy ? 'bg-green-400' : 'bg-red-400'}`}
            />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-gray-900 text-sm">{p.name}</span>
                {p.healthy ? (
                  <span className="text-xs text-green-600 font-semibold">Healthy</span>
                ) : (
                  <span className="text-xs text-red-600 font-semibold">Unavailable</span>
                )}
              </div>
              {p.error && (
                <p className="text-xs text-red-500 mt-0.5">{p.error}</p>
              )}
              <p className="text-xs text-gray-400 font-mono mt-0.5">{p.id}</p>
            </div>
            <div className="text-right flex-shrink-0">
              {p.healthy && (
                <span className="text-xs text-gray-500">{p.latency_ms} ms</span>
              )}
              <p className="text-xs text-gray-400">
                {new Date(p.last_checked).toLocaleTimeString()}
              </p>
            </div>
          </div>
        ))}
        {providers.length === 0 && (
          <p className="px-5 py-4 text-sm text-gray-400">No providers found.</p>
        )}
      </div>
    </div>
  );
}

// ─── Guardrails config panel ──────────────────────────────────────────────────

function GuardrailsPanel({
  config,
  onSave,
}: {
  config: GuardrailConfig;
  onSave: (cfg: GuardrailConfig) => Promise<void>;
}) {
  const [draft, setDraft] = useState<GuardrailConfig>(config);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(config);
  }, [config]);

  async function handleSave() {
    setSaving(true);
    await onSave(draft);
    setSaving(false);
  }

  function toggle(key: keyof GuardrailConfig) {
    setDraft((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function setNum(key: keyof GuardrailConfig, val: string) {
    const n = parseFloat(val);
    if (!isNaN(n)) setDraft((prev) => ({ ...prev, [key]: n }));
  }

  const BoolRow = ({
    label,
    description,
    field,
  }: {
    label: string;
    description: string;
    field: keyof GuardrailConfig;
  }) => (
    <div className="flex items-start justify-between py-3 border-b border-gray-50 last:border-0">
      <div className="flex-1 min-w-0 pr-4">
        <p className="text-sm font-medium text-gray-900">{label}</p>
        <p className="text-xs text-gray-500 mt-0.5">{description}</p>
      </div>
      <button
        onClick={() => toggle(field)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors flex-shrink-0 ${
          draft[field] ? 'bg-blue-600' : 'bg-gray-300'
        }`}
        role="switch"
        aria-checked={!!draft[field]}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
            draft[field] ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
    </div>
  );

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Guardrail Configuration</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Changes take effect at next model call. Constitutional hard rules cannot be disabled.
          </p>
        </div>
      </div>

      <div className="px-5 py-2">
        <BoolRow
          label="Block on Prompt Injection"
          description="Reject prompts containing known injection patterns (ignore/disregard/jailbreak). Constitutional hard rule."
          field="block_on_injection"
        />
        <BoolRow
          label="Redact Credentials"
          description="Strip AWS keys, bearer tokens, and Basic-Auth headers from prompts before dispatch."
          field="redact_credentials"
        />
        <BoolRow
          label="Redact PII"
          description="Redact email addresses, phone numbers, and credit card numbers from prompts."
          field="redact_pii"
        />

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 py-4 border-b border-gray-50">
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1 uppercase tracking-wide">
              Max Prompt Length (bytes)
            </label>
            <input
              type="number"
              min={512}
              max={32768}
              step={512}
              value={draft.max_prompt_length}
              onChange={(e) => setNum('max_prompt_length', e.target.value)}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300"
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1 uppercase tracking-wide">
              Min Confidence Threshold
            </label>
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={draft.min_confidence}
              onChange={(e) => setNum('min_confidence', e.target.value)}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300"
            />
            <p className="text-xs text-gray-400 mt-1">
              0.0 = block nothing; 1.0 = block all uncertain
            </p>
          </div>
          <div>
            <label className="block text-xs font-semibold text-gray-600 mb-1 uppercase tracking-wide">
              Rate Limit (req/min)
            </label>
            <input
              type="number"
              min={1}
              max={600}
              step={1}
              value={draft.rate_limit_rpm}
              onChange={(e) => setNum('rate_limit_rpm', e.target.value)}
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300"
            />
          </div>
        </div>
      </div>

      <div className="px-5 py-4">
        <button
          onClick={void handleSave}
          disabled={saving}
          className="px-5 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold hover:bg-blue-700 disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}

// ─── Model call audit table ───────────────────────────────────────────────────

function AuditTable({
  entries,
  total,
  page,
  provider,
  riskLevel,
  onProviderChange,
  onRiskChange,
  onPageChange,
}: {
  entries: ModelCallEntry[];
  total: number;
  page: number;
  provider: string;
  riskLevel: string;
  onProviderChange: (v: string) => void;
  onRiskChange: (v: string) => void;
  onPageChange: (v: number) => void;
}) {
  const PAGE_SIZE = 25;

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={provider}
          onChange={(e) => { onProviderChange(e.target.value); onPageChange(1); }}
          className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300 bg-white"
        >
          <option value="">All Providers</option>
          <option value="openai-codex">OpenAI Codex</option>
          <option value="anthropic-claude">Anthropic Claude</option>
          <option value="google-gemini">Google Gemini</option>
        </select>
        <select
          value={riskLevel}
          onChange={(e) => { onRiskChange(e.target.value); onPageChange(1); }}
          className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300 bg-white"
        >
          <option value="">All Risk Levels</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">Model Call Audit</h2>
          <span className="text-sm text-gray-500">{total} records</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                <th className="px-4 py-3 text-left">Time</th>
                <th className="px-4 py-3 text-left">Agent</th>
                <th className="px-4 py-3 text-left">Provider</th>
                <th className="px-4 py-3 text-left">Risk</th>
                <th className="px-4 py-3 text-left">Strategy</th>
                <th className="px-4 py-3 text-right">Latency</th>
                <th className="px-4 py-3 text-right">Tokens</th>
                <th className="px-4 py-3 text-left">Redactions</th>
                <th className="px-4 py-3 text-left">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {entries.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-gray-400">
                    No records found
                  </td>
                </tr>
              )}
              {entries.map((e) => (
                <tr key={e.call_id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-gray-600">{e.agent_id}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium text-gray-700">
                      {e.provider === 'openai-codex'
                        ? 'OpenAI Codex'
                        : e.provider === 'anthropic-claude'
                        ? 'Claude'
                        : e.provider === 'google-gemini'
                        ? 'Gemini'
                        : e.provider}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge level={e.risk_level} />
                  </td>
                  <td className="px-4 py-3">
                    <StrategyBadge strategy={e.routing_strategy} />
                  </td>
                  <td className="px-4 py-3 text-right text-xs text-gray-600">{e.latency_ms} ms</td>
                  <td className="px-4 py-3 text-right text-xs text-gray-600">
                    {e.token_count.toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    {(e.redactions ?? []).length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {(e.redactions ?? []).map((r) => (
                          <span
                            key={r}
                            className="px-1.5 py-0.5 bg-orange-50 text-orange-700 border border-orange-100 rounded text-xs"
                          >
                            {r.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {e.blocked ? (
                      <span className="inline-block px-2 py-0.5 bg-red-100 text-red-700 border border-red-200 rounded text-xs font-semibold">
                        Blocked
                      </span>
                    ) : (
                      <span className="inline-block px-2 py-0.5 bg-green-100 text-green-700 border border-green-200 rounded text-xs font-semibold">
                        Passed
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {total > PAGE_SIZE && (
          <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-between text-sm text-gray-500">
            <span>
              Page {page} of {Math.ceil(total / PAGE_SIZE)}
            </span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => onPageChange(page - 1)}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40"
              >
                Prev
              </button>
              <button
                disabled={page * PAGE_SIZE >= total}
                onClick={() => onPageChange(page + 1)}
                className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ModelGuard() {
  const { addToast } = useToast();

  const [stats, setStats] = useState<ModelGuardStatsResponse | null>(null);
  const [providers, setProviders] = useState<ProviderHealthEntry[]>([]);
  const [guardrails, setGuardrails] = useState<GuardrailConfig | null>(null);
  const [auditEntries, setAuditEntries] = useState<ModelCallEntry[]>([]);
  const [auditTotal, setAuditTotal] = useState(0);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [tab, setTab] = useState<'overview' | 'audit' | 'guardrails'>('overview');

  // Audit filters
  const [auditProvider, setAuditProvider] = useState('');
  const [auditRisk, setAuditRisk] = useState('');
  const [auditPage, setAuditPage] = useState(1);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, p, g] = await Promise.all([
        api.modelGuardStats(),
        api.modelGuardProviders(),
        api.modelGuardGuardrails(),
      ]);
      setStats(s);
      setProviders(p.providers ?? []);
      setGuardrails(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async () => {
    try {
      const res = await api.modelGuardAudit(
        auditProvider || undefined,
        auditRisk || undefined,
        auditPage,
      );
      setAuditEntries(res.entries ?? []);
      setAuditTotal(res.total ?? 0);
    } catch {
      setAuditEntries([]);
      setAuditTotal(0);
    }
  }, [auditProvider, auditRisk, auditPage]);

  useEffect(() => { void loadAll(); }, [loadAll]);
  useEffect(() => {
    if (tab === 'audit') void loadAudit();
  }, [tab, loadAudit]);

  const handleGuardrailSave = useCallback(
    async (cfg: GuardrailConfig) => {
      try {
        const res = await api.updateModelGuardGuardrails(cfg);
        setGuardrails(res.config);
        addToast('Guardrail configuration saved', 'success');
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Save failed', 'error');
      }
    },
    [addToast],
  );

  const blockedPct =
    stats && stats.total_calls > 0
      ? ((stats.blocked_calls / stats.total_calls) * 100).toFixed(1)
      : '0';

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">ModelGuard</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Model Abstraction Layer — routing, guardrails, and full model call auditing
          </p>
        </div>
        <button
          onClick={() => void loadAll()}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-800">
          {error}
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard
          label="Total Calls"
          value={stats?.total_calls ?? 0}
          sub={stats?.period ?? '24h'}
          accent="border-l-blue-400"
        />
        <StatCard
          label="Blocked"
          value={stats?.blocked_calls ?? 0}
          sub={`${blockedPct}% of total`}
          accent="border-l-red-400"
        />
        <StatCard
          label="Avg Latency"
          value={`${stats?.avg_latency_ms ?? 0} ms`}
          accent="border-l-orange-400"
        />
        <StatCard
          label="Avg Tokens"
          value={(stats?.avg_token_count ?? 0).toLocaleString()}
          accent="border-l-purple-400"
        />
        <StatCard
          label="Avg Confidence"
          value={`${((stats?.avg_confidence ?? 0) * 100).toFixed(0)}%`}
          accent="border-l-green-400"
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {(['overview', 'audit', 'guardrails'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`pb-3 text-sm font-semibold capitalize border-b-2 transition-colors ${
                tab === t
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t === 'overview'
                ? 'Overview'
                : t === 'audit'
                ? 'Model Call Audit'
                : 'Guardrails'}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Tab: Overview ── */}
      {tab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Provider health */}
          <div className="lg:col-span-1">
            <ProviderHealthPanel providers={providers} />
          </div>

          {/* Breakdown charts */}
          <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-6">
            {/* Provider breakdown */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <h2 className="text-base font-semibold text-gray-900 mb-4">Calls by Provider</h2>
              {stats?.provider_breakdown && stats.provider_breakdown.length > 0 ? (
                <BarChart items={stats.provider_breakdown} />
              ) : (
                <p className="text-sm text-gray-400">No data</p>
              )}
            </div>

            {/* Routing strategy breakdown */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <h2 className="text-base font-semibold text-gray-900 mb-4">Calls by Strategy</h2>
              {stats?.strategy_breakdown && stats.strategy_breakdown.length > 0 ? (
                <BarChart items={stats.strategy_breakdown} />
              ) : (
                <p className="text-sm text-gray-400">No data</p>
              )}
            </div>

            {/* Risk level breakdown */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <h2 className="text-base font-semibold text-gray-900 mb-4">Calls by Risk Level</h2>
              {stats?.risk_breakdown && stats.risk_breakdown.length > 0 ? (
                <BarChart items={stats.risk_breakdown} />
              ) : (
                <p className="text-sm text-gray-400">No data</p>
              )}
            </div>

            {/* Pipeline summary */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <h2 className="text-base font-semibold text-gray-900 mb-4">Pipeline Stages</h2>
              <ol className="space-y-3">
                {[
                  {
                    label: 'Prompt Sanitization',
                    desc: 'Strip PII, credentials, injection patterns',
                    color: 'bg-blue-500',
                  },
                  {
                    label: 'Tool Intent Check',
                    desc: 'Validate tool calls against agent allowlist',
                    color: 'bg-purple-500',
                  },
                  {
                    label: 'Provider Dispatch',
                    desc: 'Route by risk level — single / fallback / quorum',
                    color: 'bg-green-500',
                  },
                  {
                    label: 'Output Validation',
                    desc: 'Schema check, confidence threshold, guardrails',
                    color: 'bg-orange-500',
                  },
                  {
                    label: 'Audit Logging',
                    desc: 'Append tamper-evident record with SHA-256 hash',
                    color: 'bg-gray-500',
                  },
                ].map((stage, idx) => (
                  <li key={stage.label} className="flex items-start gap-3">
                    <div
                      className={`w-6 h-6 rounded-full ${stage.color} text-white text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5`}
                    >
                      {idx + 1}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{stage.label}</p>
                      <p className="text-xs text-gray-400">{stage.desc}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Model Call Audit ── */}
      {tab === 'audit' && (
        <AuditTable
          entries={auditEntries}
          total={auditTotal}
          page={auditPage}
          provider={auditProvider}
          riskLevel={auditRisk}
          onProviderChange={setAuditProvider}
          onRiskChange={setAuditRisk}
          onPageChange={(p) => {
            setAuditPage(p);
          }}
        />
      )}

      {/* ── Tab: Guardrails ── */}
      {tab === 'guardrails' && guardrails && (
        <GuardrailsPanel config={guardrails} onSave={handleGuardrailSave} />
      )}
      {tab === 'guardrails' && !guardrails && !loading && (
        <div className="bg-white rounded-lg border border-gray-200 p-8 text-center text-gray-400">
          Could not load guardrail configuration.
        </div>
      )}
    </div>
  );
}
