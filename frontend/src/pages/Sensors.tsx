import { useCallback, useEffect, useMemo, useState } from 'react';
import { api, type SensorInfo } from '../api';

// ─── Per-sensor colour palette ────────────────────────────────────────────────

const SENSOR_META: Record<string, { icon: string; accent: string; tag: string; tagColor: string }> = {
  hostguard: {
    icon: '🖥️',
    accent: 'border-l-blue-500',
    tag: 'Host',
    tagColor: 'bg-blue-50 text-blue-700 border-blue-200',
  },
  agentguard: {
    icon: '🤖',
    accent: 'border-l-purple-500',
    tag: 'Agent',
    tagColor: 'bg-purple-50 text-purple-700 border-purple-200',
  },
  commsguard: {
    icon: '💬',
    accent: 'border-l-green-500',
    tag: 'Comms',
    tagColor: 'bg-green-50 text-green-700 border-green-200',
  },
};

const FALLBACK_META = {
  icon: '🔬',
  accent: 'border-l-gray-400',
  tag: 'Sensor',
  tagColor: 'bg-gray-100 text-gray-600 border-gray-200',
};

// Subsystem pill colours cycle through a palette based on index
const SUB_PALETTE = [
  'bg-blue-50 text-blue-700 border-blue-100',
  'bg-purple-50 text-purple-700 border-purple-100',
  'bg-green-50 text-green-700 border-green-100',
  'bg-orange-50 text-orange-700 border-orange-100',
  'bg-pink-50 text-pink-700 border-pink-100',
  'bg-teal-50 text-teal-700 border-teal-100',
  'bg-yellow-50 text-yellow-700 border-yellow-100',
];

// ─── Copy-to-clipboard helper ─────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }
  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      className="ml-1.5 text-gray-300 hover:text-gray-600 transition-colors text-xs select-none"
    >
      {copied ? '✓' : '⎘'}
    </button>
  );
}

// ─── Config table ─────────────────────────────────────────────────────────────

function ConfigTable({ config }: { config: Record<string, unknown> }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
            <th className="px-4 py-2.5 text-left w-56">Key</th>
            <th className="px-4 py-2.5 text-left">Value</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {Object.entries(config).map(([key, value]) => (
            <tr key={key} className="hover:bg-gray-50 group">
              <td className="px-4 py-2.5 font-mono text-xs text-gray-500 align-top whitespace-nowrap">
                {key}
              </td>
              <td className="px-4 py-2.5 align-top">
                {Array.isArray(value) ? (
                  <ul className="space-y-0.5">
                    {(value as unknown[]).map((v, i) => (
                      <li key={i} className="flex items-center gap-1">
                        <span className="font-mono text-xs text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded">
                          {String(v)}
                        </span>
                        <CopyButton text={String(v)} />
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="flex items-center gap-1">
                    <code className="font-mono text-xs text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded">
                      {String(value)}
                    </code>
                    <span className="opacity-0 group-hover:opacity-100 transition-opacity">
                      <CopyButton text={String(value)} />
                    </span>
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Sensor card ──────────────────────────────────────────────────────────────

function SensorCard({ sensor, highlight }: { sensor: SensorInfo; highlight: string }) {
  const [showConfig, setShowConfig] = useState(false);
  const meta = SENSOR_META[sensor.id] ?? FALLBACK_META;

  // Determine whether it's using NATS or an HTTP listen address
  const isNats = sensor.listen_addr.toLowerCase().includes('nats');
  const natsTopic = sensor.config['nats_topic'] as string | undefined;

  // Highlight matching subsystems when search is active
  const highlightedSubs = useMemo(() => {
    if (!highlight) return sensor.subsystems;
    const lc = highlight.toLowerCase();
    return sensor.subsystems.filter((s) => s.toLowerCase().includes(lc));
  }, [sensor.subsystems, highlight]);

  const showAll = !highlight;

  return (
    <div
      className={`bg-white rounded-xl shadow-sm border border-gray-200 border-l-4 ${meta.accent} overflow-hidden`}
    >
      {/* ── Card header ── */}
      <div className="px-6 py-5">
        <div className="flex items-start gap-4">
          <span className="text-3xl flex-shrink-0 mt-0.5">{meta.icon}</span>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <h2 className="text-lg font-bold text-gray-900">{sensor.name}</h2>
              <span
                className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${meta.tagColor}`}
              >
                {meta.tag}
              </span>
              {/* Status pill — always shown as Active since the API returns configured sensors */}
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-green-50 border border-green-200 text-green-700 text-xs font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                Active
              </span>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed">{sensor.description}</p>
          </div>
        </div>

        {/* ── Listen / NATS row ── */}
        <div className="mt-4 flex flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
              {isNats ? 'Transport' : 'Listen'}
            </span>
            <span className="flex items-center gap-1 font-mono text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded-lg">
              {isNats ? '📨 NATS' : sensor.listen_addr}
              {!isNats && <CopyButton text={sensor.listen_addr} />}
            </span>
          </div>
          {natsTopic && (
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Topic</span>
              <span className="flex items-center gap-1 font-mono text-xs bg-indigo-50 text-indigo-700 px-2 py-1 rounded-lg">
                {natsTopic}
                <CopyButton text={natsTopic} />
              </span>
            </div>
          )}
        </div>

        {/* ── Subsystem pills ── */}
        <div className="mt-4">
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
            Subsystems / Channels ({sensor.subsystems.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {(showAll ? sensor.subsystems : highlightedSubs).map((sub, idx) => (
              <span
                key={sub}
                className={`inline-block px-2.5 py-1 rounded-full border text-xs font-medium ${
                  SUB_PALETTE[idx % SUB_PALETTE.length]
                }${
                  highlight && sub.toLowerCase().includes(highlight.toLowerCase())
                    ? ' ring-2 ring-offset-1 ring-yellow-400'
                    : ''
                }`}
              >
                {sub.replace(/_/g, ' ')}
              </span>
            ))}
            {!showAll && highlightedSubs.length === 0 && (
              <span className="text-xs text-gray-400">No matching subsystems</span>
            )}
            {!showAll && highlightedSubs.length < sensor.subsystems.length && (
              <span className="text-xs text-gray-400 self-center">
                +{sensor.subsystems.length - highlightedSubs.length} more hidden
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Config toggle ── */}
      <div className="border-t border-gray-100">
        <button
          onClick={() => setShowConfig((v) => !v)}
          className="w-full flex items-center justify-between px-6 py-3 text-sm text-gray-500 hover:bg-gray-50 transition-colors font-medium"
        >
          <span className="flex items-center gap-2">
            <span className="text-gray-400">⚙️</span>
            Default Configuration
            <span className="text-xs text-gray-400">
              ({Object.keys(sensor.config).length} keys)
            </span>
          </span>
          <span className={`transition-transform duration-200 ${showConfig ? 'rotate-180' : ''}`}>
            ▾
          </span>
        </button>

        {showConfig && (
          <div className="border-t border-gray-100">
            <ConfigTable config={sensor.config} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Summary stat card ────────────────────────────────────────────────────────

function StatPill({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 shadow-sm px-5 py-4 flex items-center gap-4">
      <p className="text-3xl font-bold text-gray-900">{value}</p>
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide leading-tight">{label}</p>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Sensors() {
  const [sensors, setSensors] = useState<SensorInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.sensors()
      .then((res) => setSensors(res.sensors))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const filteredSensors = useMemo(() => {
    const lc = search.toLowerCase();
    if (!lc) return sensors;
    return sensors.filter(
      (s) =>
        s.name.toLowerCase().includes(lc) ||
        s.id.toLowerCase().includes(lc) ||
        s.description.toLowerCase().includes(lc) ||
        s.subsystems.some((sub) => sub.toLowerCase().includes(lc)),
    );
  }, [sensors, search]);

  const totalSubsystems = sensors.reduce((acc, s) => acc + s.subsystems.length, 0);

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Sensors</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Deployed sensor adapters, their subsystems, and default configurations
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold hover:bg-blue-700 disabled:opacity-50 flex-shrink-0"
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {/* ── Summary stats ── */}
      {!loading && sensors.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <StatPill label="Sensors Deployed" value={sensors.length} />
          <StatPill label="Active Subsystems" value={totalSubsystems} />
          <StatPill label="Transport Channels" value="NATS + HTTP" />
        </div>
      )}

      {/* ── Search bar ── */}
      {!loading && sensors.length > 0 && (
        <div className="relative">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm pointer-events-none">
            🔍
          </span>
          <input
            type="text"
            placeholder="Search sensors, subsystems, or descriptions…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-300 bg-white shadow-sm"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 text-sm"
            >
              ✕
            </button>
          )}
        </div>
      )}

      {/* ── Error ── */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-800 flex items-center gap-2">
          <span>⚠️</span> {error}
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="flex items-center justify-center py-16 text-gray-400 text-sm gap-2">
          <span className="animate-spin">⏳</span> Loading sensors…
        </div>
      )}

      {/* ── Empty state ── */}
      {!loading && sensors.length === 0 && !error && (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
          <p className="text-4xl mb-3">🔬</p>
          <p className="text-gray-600 font-medium">No sensors available</p>
          <p className="text-gray-400 text-sm mt-1">
            Start a sensor adapter to see it here.
          </p>
        </div>
      )}

      {/* ── No search results ── */}
      {!loading && sensors.length > 0 && filteredSensors.length === 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-10 text-center">
          <p className="text-3xl mb-2">🔍</p>
          <p className="text-gray-600 font-medium">No sensors match "{search}"</p>
          <button
            onClick={() => setSearch('')}
            className="mt-3 text-sm text-blue-600 hover:underline"
          >
            Clear search
          </button>
        </div>
      )}

      {/* ── Sensor cards ── */}
      {!loading && filteredSensors.length > 0 && (
        <div className="space-y-5">
          {filteredSensors.map((sensor) => (
            <SensorCard key={sensor.id} sensor={sensor} highlight={search} />
          ))}
        </div>
      )}

      {/* ── Search result count ── */}
      {search && filteredSensors.length > 0 && (
        <p className="text-xs text-gray-400 text-center">
          Showing {filteredSensors.length} of {sensors.length} sensors
        </p>
      )}
    </div>
  );
}
