import { useEffect, useState } from 'react';
import { api, type WebhookConfig } from '../api';
import { useToast } from '../contexts/ToastContext';

const FORMATS = ['generic', 'slack', 'pagerduty'] as const;
type Format = typeof FORMATS[number];

const TIER_LABELS: Record<number, string> = { 0: 'T0+', 1: 'T1+', 2: 'T2+', 3: 'T3+', 4: 'T4 only' };
const TIER_COLOR: Record<number, string> = { 0: '#64748b', 1: '#22c55e', 2: '#f59e0b', 3: '#f97316', 4: '#ef4444' };
const FORMAT_ICON: Record<string, string> = { slack: '💬', pagerduty: '🚨', generic: '🔗' };

const defaultWh = (): Omit<WebhookConfig, 'id' | 'created_at'> => ({
  name: '', url: '', min_tier: 2, format: 'generic', enabled: true,
});

// ── shared style tokens (mirrors AccountSettings) ──────────────────────────
const card: React.CSSProperties = {
  background: '#1e293b',
  borderRadius: '12px',
  border: '1px solid #334155',
  padding: '2rem',
};

const label: React.CSSProperties = {
  display: 'block',
  fontSize: '0.8125rem',
  fontWeight: 600,
  color: '#94a3b8',
  marginBottom: '0.375rem',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
};

const input: React.CSSProperties = {
  width: '100%',
  background: '#0f172a',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#f1f5f9',
  fontSize: '0.9375rem',
  padding: '0.625rem 0.875rem',
  outline: 'none',
  boxSizing: 'border-box',
};

const sectionHead: React.CSSProperties = {
  fontSize: '0.6875rem',
  fontWeight: 700,
  color: '#475569',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  marginBottom: '0.875rem',
  marginTop: '1.5rem',
  paddingBottom: '0.375rem',
  borderBottom: '1px solid #334155',
};

const primaryBtn = (disabled = false): React.CSSProperties => ({
  background: disabled ? '#1e3a5f' : '#2563eb',
  color: '#fff',
  border: 'none',
  borderRadius: '8px',
  padding: '0.625rem 1.25rem',
  fontWeight: 700,
  fontSize: '0.875rem',
  cursor: disabled ? 'not-allowed' : 'pointer',
  whiteSpace: 'nowrap',
});

const dangerBtn = (disabled = false): React.CSSProperties => ({
  background: '#1a0a0a',
  color: disabled ? '#6b2b2b' : '#ef4444',
  border: '1px solid #7f1d1d',
  borderRadius: '8px',
  padding: '0.625rem 1.25rem',
  fontWeight: 600,
  fontSize: '0.875rem',
  cursor: disabled ? 'not-allowed' : 'pointer',
  whiteSpace: 'nowrap',
});

const ghostBtn = (disabled = false): React.CSSProperties => ({
  background: disabled ? '#0f172a' : '#0f172a',
  color: disabled ? '#1d4ed8' : '#3b82f6',
  border: '1px solid #1e3a5f',
  borderRadius: '8px',
  padding: '0.625rem 1.25rem',
  fontWeight: 600,
  fontSize: '0.875rem',
  cursor: disabled ? 'not-allowed' : 'pointer',
  whiteSpace: 'nowrap',
});

// ── component ───────────────────────────────────────────────────────────────
export default function WebhookSettings() {
  const { addToast } = useToast();
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [form, setForm] = useState(defaultWh());
  const [saving, setSaving] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function load() {
    try {
      const res = await api.listWebhooks();
      setWebhooks(res.webhooks);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name || !form.url) return;
    setCreating(true);
    try {
      await api.createWebhook(form);
      addToast(`Webhook "${form.name}" created`, 'success');
      setForm(defaultWh());
      await load();
    } catch (err: unknown) {
      addToast(`Create failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setCreating(false); }
  }

  async function handleToggle(wh: WebhookConfig) {
    setSaving(wh.id);
    try {
      await api.updateWebhook(wh.id, { enabled: !wh.enabled });
      addToast(`Webhook ${wh.enabled ? 'disabled' : 'enabled'}`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Update failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setSaving(null); }
  }

  async function handleDelete(wh: WebhookConfig) {
    if (!confirm(`Delete webhook "${wh.name}"?`)) return;
    try {
      await api.deleteWebhook(wh.id);
      addToast(`Webhook "${wh.name}" deleted`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Delete failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  }

  return (
    <div style={{ padding: '2rem' }}>
      {/* Page header */}
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.5rem' }}>
        🔔 Webhook Settings
      </h1>
      <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '2rem' }}>
        Configure outbound alert webhooks for incident notifications.
      </p>

      {error && (
        <div style={{ background: '#1a0a0a', border: '1px solid #7f1d1d', borderRadius: '8px', color: '#ef4444', padding: '0.75rem 1rem', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
          ⚠️ {error}
        </div>
      )}

      {/* ── Add Webhook ───────────────────────────────────────────────────── */}
      <div style={{ ...card, maxWidth: '600px', marginBottom: '2rem' }}>
        <form onSubmit={handleCreate}>
          <div style={{ ...sectionHead, marginTop: 0 }}>New webhook</div>

          <div style={{ display: 'flex', gap: '0.875rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 160px' }}>
              <label style={label}>Name</label>
              <input
                style={input}
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Slack Security"
                required
              />
            </div>
            <div style={{ flex: '2 1 260px' }}>
              <label style={label}>Webhook URL</label>
              <input
                style={input}
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                placeholder="https://hooks.slack.com/…"
                required
                autoComplete="off"
              />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.875rem', marginBottom: '1.75rem', flexWrap: 'wrap' }}>
            <div style={{ flex: '1 1 140px' }}>
              <label style={label}>Minimum tier</label>
              <select
                style={{ ...input, cursor: 'pointer' }}
                value={form.min_tier}
                onChange={(e) => setForm((f) => ({ ...f, min_tier: Number(e.target.value) }))}
              >
                {[0, 1, 2, 3, 4].map((t) => <option key={t} value={t}>{TIER_LABELS[t]}</option>)}
              </select>
            </div>
            <div style={{ flex: '1 1 140px' }}>
              <label style={label}>Format</label>
              <select
                style={{ ...input, cursor: 'pointer' }}
                value={form.format}
                onChange={(e) => setForm((f) => ({ ...f, format: e.target.value as Format }))}
              >
                {FORMATS.map((fmt) => <option key={fmt} value={fmt}>{FORMAT_ICON[fmt]} {fmt.charAt(0).toUpperCase() + fmt.slice(1)}</option>)}
              </select>
            </div>
          </div>

          <button type="submit" disabled={creating} style={primaryBtn(creating)}>
            {creating ? 'Creating…' : '+ Add webhook'}
          </button>
        </form>
      </div>

      {/* ── Webhook list ──────────────────────────────────────────────────── */}
      <div style={{ ...sectionHead, marginTop: 0, maxWidth: '760px' }}>
        Configured webhooks
      </div>

      {loading ? (
        <p style={{ color: '#475569', fontStyle: 'italic' }}>Loading…</p>
      ) : webhooks.length === 0 ? (
        <div style={{ ...card, maxWidth: '760px', textAlign: 'center', color: '#475569', fontStyle: 'italic' }}>
          No webhooks configured. Add one above to start receiving alerts.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: '760px' }}>
          {webhooks.map((wh) => (
            <div key={wh.id} style={{ ...card, opacity: wh.enabled ? 1 : 0.6 }}>
              {/* Webhook header */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '1rem' }}>
                <span style={{ fontSize: '1.4rem', lineHeight: 1, flexShrink: 0, marginTop: '0.1rem' }}>
                  {FORMAT_ICON[wh.format] ?? '🔗'}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>{wh.name}</div>
                  <div style={{
                    fontFamily: 'monospace', fontSize: '0.78rem', color: '#64748b',
                    marginTop: '0.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {wh.url}
                  </div>
                </div>
                {/* Status pill */}
                <span style={{
                  flexShrink: 0,
                  background: wh.enabled ? '#14532d' : '#1e293b',
                  color: wh.enabled ? '#22c55e' : '#475569',
                  border: `1px solid ${wh.enabled ? '#166534' : '#334155'}`,
                  borderRadius: '6px',
                  padding: '0.2rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                }}>
                  {wh.enabled ? '● Active' : '○ Disabled'}
                </span>
              </div>

              {/* Meta row */}
              <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
                <span style={{
                  background: `${TIER_COLOR[wh.min_tier] ?? '#64748b'}22`,
                  color: TIER_COLOR[wh.min_tier] ?? '#64748b',
                  border: `1px solid ${TIER_COLOR[wh.min_tier] ?? '#64748b'}55`,
                  borderRadius: '6px',
                  padding: '0.2rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                }}>
                  {TIER_LABELS[wh.min_tier]}
                </span>
                <span style={{
                  background: '#1e293b',
                  color: '#94a3b8',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  padding: '0.2rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  textTransform: 'capitalize',
                }}>
                  {wh.format}
                </span>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: '0.625rem' }}>
                <button
                  disabled={saving === wh.id}
                  onClick={() => handleToggle(wh)}
                  style={wh.enabled ? dangerBtn(saving === wh.id) : ghostBtn(saving === wh.id)}
                >
                  {saving === wh.id ? '…' : wh.enabled ? 'Disable' : 'Enable'}
                </button>
                <button onClick={() => handleDelete(wh)} style={dangerBtn()}>
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

