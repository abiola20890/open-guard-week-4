import { useEffect, useState } from 'react';
import { api, type SupplyChainEvent, type SupplyChainStats } from '../api';

// ── shared style tokens (mirrors AccountSettings) ──────────────────────────
const card: React.CSSProperties = {
  background: '#1e293b',
  borderRadius: '12px',
  border: '1px solid #334155',
  padding: '2rem',
};

const sectionHead: React.CSSProperties = {
  fontSize: '0.6875rem',
  fontWeight: 700,
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  marginBottom: '0.875rem',
  paddingBottom: '0.375rem',
  borderBottom: '1px solid #334155',
};

// Risk score → colour
function riskColor(score: number) {
  if (score >= 70) return '#ef4444';
  if (score >= 40) return '#f59e0b';
  return '#22c55e';
}

function RiskBadge({ label, score }: { label: string; score: number }) {
  const c = riskColor(score);
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
      background: `${c}18`, color: c, border: `1px solid ${c}44`,
      borderRadius: '6px', padding: '0.2rem 0.55rem',
      fontSize: '0.75rem', fontWeight: 700,
    }}>
      {label} <span style={{ opacity: 0.75 }}>({score.toFixed(0)})</span>
    </span>
  );
}

function Flag({ text }: { text: string }) {
  return (
    <span style={{
      background: '#ef444418', color: '#ef4444', border: '1px solid #ef444444',
      borderRadius: '4px', padding: '0.1rem 0.45rem',
      fontSize: '0.72rem', fontWeight: 600, marginRight: '0.25rem',
    }}>
      {text}
    </span>
  );
}

const INSTALLER_ICON: Record<string, string> = {
  npm: '📦', pip: '🐍', cargo: '🦀', go: '🐹', apt: '🐧', brew: '🍺', yarn: '🧶',
};

// ── component ───────────────────────────────────────────────────────────────
export default function SupplyChainGuard() {
  const [events, setEvents] = useState<SupplyChainEvent[]>([]);
  const [stats, setStats] = useState<SupplyChainStats | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load(pg: number) {
    setLoading(true);
    try {
      const [res, st] = await Promise.all([api.supplyChain(pg), api.supplyChainStats()]);
      setEvents(res.events ?? []);
      setTotal(res.total ?? 0);
      setStats(st);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(page); }, [page]);

  const totalPages = Math.max(1, Math.ceil(total / 50));

  return (
    <div style={{ padding: '2rem' }}>
      {/* Page header */}
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.5rem' }}>
        📦 Supply Chain Guard
      </h1>
      <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '2rem' }}>
        Detected package-manager invocations and typosquatting risk indicators from host telemetry.
      </p>

      {error && (
        <div style={{ background: '#1a0a0a', border: '1px solid #7f1d1d', borderRadius: '8px', color: '#ef4444', padding: '0.75rem 1rem', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
          ⚠️ {error}
        </div>
      )}

      {/* ── Stats ─────────────────────────────────────────────────────────── */}
      {stats && (
        <>
          <div style={{ ...sectionHead }}>Overview</div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '2rem' }}>
            {/* Total */}
            <div style={{ ...card, minWidth: '120px', textAlign: 'center', padding: '1.25rem 1.5rem', flex: '0 0 auto' }}>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f1f5f9', lineHeight: 1 }}>
                {stats.total}
              </div>
              <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: '0.5rem' }}>
                Total events
              </div>
            </div>
            {/* High risk */}
            <div style={{ ...card, minWidth: '120px', textAlign: 'center', padding: '1.25rem 1.5rem', flex: '0 0 auto', borderColor: stats.high_risk > 0 ? '#7f1d1d' : '#334155' }}>
              <div style={{ fontSize: '2rem', fontWeight: 800, color: stats.high_risk > 0 ? '#ef4444' : '#f1f5f9', lineHeight: 1 }}>
                {stats.high_risk}
              </div>
              <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: '0.5rem' }}>
                High risk
              </div>
            </div>
            {/* Per installer */}
            {Object.entries(stats.installers ?? {}).map(([k, v]) => (
              <div key={k} style={{ ...card, minWidth: '100px', textAlign: 'center', padding: '1.25rem 1.5rem', flex: '0 0 auto' }}>
                <div style={{ fontSize: '1.1rem', marginBottom: '0.2rem' }}>{INSTALLER_ICON[k] ?? '📦'}</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f1f5f9', lineHeight: 1 }}>{v}</div>
                <div style={{ fontSize: '0.6875rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: '0.5rem' }}>
                  {k}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ── Event table ───────────────────────────────────────────────────── */}
      <div style={sectionHead}>Events {total > 0 && <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>({total})</span>}</div>

      {loading ? (
        <p style={{ color: '#475569', fontStyle: 'italic' }}>Loading…</p>
      ) : events.length === 0 ? (
        <div style={{ ...card, textAlign: 'center', color: '#475569', fontStyle: 'italic' }}>
          No supply-chain events detected yet. Package manager invocations will appear here once HostGuard telemetry is processed.
        </div>
      ) : (
        <>
          <div style={{ ...card, padding: 0, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ background: '#0f172a' }}>
                  {['Time', 'Host', 'Installer', 'Package', 'Version', 'Risk', 'Flags'].map((h) => (
                    <th key={h} style={{
                      padding: '0.75rem 1rem',
                      textAlign: 'left',
                      fontSize: '0.6875rem',
                      fontWeight: 700,
                      color: '#475569',
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      borderBottom: '1px solid #334155',
                      whiteSpace: 'nowrap',
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr
                    key={ev.id}
                    style={{ background: i % 2 === 0 ? '#1e293b' : '#182032', borderBottom: '1px solid #1e293b' }}
                  >
                    <td style={{ padding: '0.75rem 1rem', color: '#64748b', whiteSpace: 'nowrap', fontSize: '0.78rem' }}>
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#94a3b8' }}>
                        {ev.host || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{
                        background: '#0f172a', border: '1px solid #334155',
                        borderRadius: '6px', padding: '0.2rem 0.55rem',
                        fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600,
                      }}>
                        {INSTALLER_ICON[ev.installer] ?? ''} {ev.installer}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 700, color: '#f1f5f9' }}>
                      {ev.package_name}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: '#64748b', fontSize: '0.82rem' }}>
                      {ev.version ?? '—'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <RiskBadge label={ev.risk_label} score={ev.risk_score} />
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {(ev.flags ?? []).map((f) => <Flag key={f} text={f} />)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', justifyContent: 'center', marginTop: '1.5rem' }}>
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                style={{
                  background: page <= 1 ? '#0f172a' : '#1e293b',
                  color: page <= 1 ? '#334155' : '#94a3b8',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '0.5rem 1rem',
                  fontWeight: 600,
                  fontSize: '0.875rem',
                  cursor: page <= 1 ? 'not-allowed' : 'pointer',
                }}
              >
                ← Prev
              </button>
              <span style={{ color: '#475569', fontSize: '0.875rem' }}>
                Page {page} / {totalPages}
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
                style={{
                  background: page >= totalPages ? '#0f172a' : '#1e293b',
                  color: page >= totalPages ? '#334155' : '#94a3b8',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  padding: '0.5rem 1rem',
                  fontWeight: 600,
                  fontSize: '0.875rem',
                  cursor: page >= totalPages ? 'not-allowed' : 'pointer',
                }}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

