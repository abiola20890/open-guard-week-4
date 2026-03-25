import type {
  EventsResponse,
  IncidentsResponse,
  HostStatsResponse,
  AgentStatsResponse,
  ModelGuardStatsResponse,
  CommsStatsResponse,
  NetStatsResponse,
} from '../api';

interface KPIChartsProps {
  events: EventsResponse | null;
  incidents: IncidentsResponse | null;
  hostStats: HostStatsResponse | null;
  agentStats: AgentStatsResponse | null;
  modelStats: ModelGuardStatsResponse | null;
  commsStats: CommsStatsResponse | null;
  netStats: NetStatsResponse | null;
}

// ── SVG Donut Chart ─────────────────────────────────────────────────────────
interface DonutSegment { label: string; value: number; color: string }

function DonutChart({ segments, centerLabel }: { segments: DonutSegment[]; centerLabel: string }) {
  const r = 38;
  const circ = 2 * Math.PI * r; // ≈ 238.76
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  let accumulated = 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
      {/* Donut */}
      <div style={{ position: 'relative', width: 140, height: 140 }}>
        <svg width={140} height={140} viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          {/* background track */}
          <circle cx={50} cy={50} r={r} fill="none" stroke="#1e293b" strokeWidth={16} />
          {total > 0 && segments.map((seg, i) => {
            const frac = seg.value / total;
            if (frac <= 0) return null;
            const dashOffset = circ * (1 - accumulated);
            accumulated += frac;
            return (
              <circle
                key={i}
                cx={50} cy={50} r={r}
                fill="none"
                stroke={seg.color}
                strokeWidth={16}
                strokeDasharray={`${frac * circ} ${circ}`}
                strokeDashoffset={dashOffset}
              />
            );
          })}
        </svg>
        {/* centre label */}
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <span style={{ fontSize: '1.625rem', fontWeight: 700, color: '#f1f5f9', lineHeight: 1 }}>
            {total}
          </span>
          <span style={{ fontSize: '0.6rem', color: '#64748b', marginTop: '2px' }}>
            {centerLabel}
          </span>
        </div>
      </div>
      {/* legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', width: '100%' }}>
        {segments.map((seg) => (
          <div key={seg.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{
                width: 9, height: 9, borderRadius: 2,
                background: seg.color, flexShrink: 0, display: 'inline-block',
              }} />
              <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{seg.label}</span>
            </div>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#cbd5e1' }}>{seg.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Vertical Bar Chart ──────────────────────────────────────────────────────
interface BarDatum { label: string; value: number; color: string }

function VerticalBars({ bars }: { bars: BarDatum[] }) {
  const max = Math.max(...bars.map((b) => b.value), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '0.5rem', height: 110 }}>
        {bars.map((bar) => (
          <div key={bar.label} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1 }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '3px' }}>
              {bar.value}
            </span>
            <div style={{
              width: '100%',
              height: `${Math.max((bar.value / max) * 100, bar.value > 0 ? 3 : 0)}%`,
              background: bar.color,
              borderRadius: '3px 3px 0 0',
              transition: 'height 0.4s ease',
            }} />
          </div>
        ))}
      </div>
      {/* x-axis labels */}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        {bars.map((bar) => (
          <div key={bar.label} style={{ flex: 1, textAlign: 'center' }}>
            <span style={{ fontSize: '0.65rem', color: '#64748b' }}>{bar.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Horizontal Bar Chart ────────────────────────────────────────────────────
function HorizontalBars({ bars }: { bars: BarDatum[] }) {
  const max = Math.max(...bars.map((b) => b.value), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem', flex: 1, justifyContent: 'center' }}>
      {bars.map((bar) => (
        <div key={bar.label}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{bar.label}</span>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#cbd5e1' }}>{bar.value}</span>
          </div>
          <div style={{ background: '#1e293b', borderRadius: 4, height: 7, overflow: 'hidden' }}>
            <div style={{
              width: `${(bar.value / max) * 100}%`,
              height: '100%',
              background: bar.color,
              borderRadius: 4,
              minWidth: bar.value > 0 ? 6 : 0,
              transition: 'width 0.4s ease',
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// parseTierNum converts a tier value that may be a string ("T0"–"T4") or a
// legacy number into its numeric equivalent. Returns undefined for unrecognised values.
function parseTierNum(t: unknown): number | undefined {
  if (typeof t === 'number') return t;
  if (typeof t === 'string') {
    if (/^T(\d)$/i.test(t)) return parseInt(t.slice(1), 10);
    const n = parseInt(t, 10);
    if (!isNaN(n)) return n;
  }
  return undefined;
}

// ── KPICharts ───────────────────────────────────────────────────────────────
export default function KPICharts({
  events,
  incidents,
  hostStats,
  agentStats,
  modelStats,
  commsStats,
  netStats,
}: KPIChartsProps) {
  // Tier distribution (T0–T4)
  const TIER_COLORS: Record<number, string> = {
    0: '#334155', 1: '#1d4ed8', 2: '#d97706', 3: '#ea580c', 4: '#dc2626',
  };
  const tierSegments: DonutSegment[] = [0, 1, 2, 3, 4].map((tier) => ({
    label: `T${tier}`,
    value: events?.events.filter((e) => parseTierNum(e.tier) === tier).length ?? 0,
    color: TIER_COLORS[tier],
  }));

  // Risk score distribution (4 bands)
  const riskBars: BarDatum[] = [
    { label: '0–25',   color: '#16a34a', value: 0 },
    { label: '26–50',  color: '#d97706', value: 0 },
    { label: '51–75',  color: '#ea580c', value: 0 },
    { label: '76–100', color: '#dc2626', value: 0 },
  ];
  const RISK_RANGES = [[0, 25], [26, 50], [51, 75], [76, 100]] as const;
  for (const ev of events?.events ?? []) {
    const s = ev.risk_score as number | undefined;
    if (s === undefined) continue;
    for (let i = 0; i < RISK_RANGES.length; i++) {
      if (s >= RISK_RANGES[i][0] && s <= RISK_RANGES[i][1]) { riskBars[i].value++; break; }
    }
  }

  // Incident status
  const incidentSegments: DonutSegment[] = [
    { label: 'Pending',  color: '#d97706', value: incidents?.incidents.filter((i) => i.status === 'pending').length  ?? 0 },
    { label: 'Approved', color: '#16a34a', value: incidents?.incidents.filter((i) => i.status === 'approved').length ?? 0 },
    { label: 'Denied',   color: '#dc2626', value: incidents?.incidents.filter((i) => i.status === 'denied').length   ?? 0 },
  ];
  const totalIncidents = incidents?.total ?? 0;

  // Threats detected per guard
  const guardBars: BarDatum[] = [
    { label: '🖥️ Host',  color: '#ea580c', value: hostStats?.threat_events    ?? 0 },
    { label: '🤖 Agent', color: '#7c3aed', value: agentStats?.total_threats   ?? 0 },
    { label: '💬 Comms', color: '#0891b2', value: commsStats?.total_threats   ?? 0 },
    { label: '🌐 Net',   color: '#22c55e', value: netStats?.threat_events     ?? 0 },
    { label: '🧠 Model', color: '#2563eb', value: modelStats?.blocked_calls   ?? 0 },
  ];

  const sectionTitle: React.CSSProperties = {
    fontSize: '0.75rem',
    fontWeight: 600,
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    marginBottom: '1rem',
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1.5rem' }}>
        <span>📊</span>
        <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.9375rem' }}>
          OpenGuard Key Performance Indicators
        </span>
        <span style={{
          marginLeft: 'auto',
          fontSize: '0.7rem', color: '#475569',
          border: '1px solid #334155', borderRadius: '4px', padding: '1px 6px',
        }}>
          live
        </span>
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '2rem 2.5rem',
        alignItems: 'start',
      }}>
        {/* 1 — Tier Distribution */}
        <div>
          <div style={sectionTitle}>Tier Distribution</div>
          <DonutChart segments={tierSegments} centerLabel="Events" />
        </div>

        {/* 2 — Risk Score Distribution */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={sectionTitle}>Risk Score Distribution</div>
          <VerticalBars bars={riskBars} />
        </div>

        {/* 3 — Incident Status */}
        <div>
          <div style={sectionTitle}>Incident Status</div>
          <DonutChart
            segments={incidentSegments}
            centerLabel={`of ${totalIncidents}`}
          />
        </div>

        {/* 4 — Threats by Guard */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={sectionTitle}>Threats by Guard</div>
          <HorizontalBars bars={guardBars} />
        </div>
      </div>
    </div>
  );
}
