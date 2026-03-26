import { useEffect, useState } from 'react';
import { api, type UserRecord } from '../api';
import { useToast } from '../contexts/ToastContext';

const ROLES = ['viewer', 'analyst', 'operator', 'admin'] as const;
type Role = typeof ROLES[number];

const ROLE_COLOR: Record<string, string> = {
  admin: '#f59e0b',
  operator: '#3b82f6',
  analyst: '#22c55e',
  viewer: '#64748b',
};

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
  background: disabled ? '#2d1515' : '#1a0a0a',
  color: disabled ? '#6b2b2b' : '#ef4444',
  border: '1px solid #7f1d1d',
  borderRadius: '8px',
  padding: '0.625rem 1.25rem',
  fontWeight: 600,
  fontSize: '0.875rem',
  cursor: disabled ? 'not-allowed' : 'pointer',
  whiteSpace: 'nowrap',
});

// ── component ───────────────────────────────────────────────────────────────
export default function UserManagement() {
  const { addToast } = useToast();
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<Role>('viewer');
  const [creating, setCreating] = useState(false);

  const [editRole, setEditRole] = useState<Record<string, Role>>({});
  const [editPwd, setEditPwd] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);

  async function load() {
    try {
      const res = await api.listUsers();
      setUsers(res.users);
      const roles: Record<string, Role> = {};
      const pwds: Record<string, string> = {};
      for (const u of res.users) { roles[u.username] = u.role; pwds[u.username] = ''; }
      setEditRole(roles);
      setEditPwd(pwds);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newUsername || !newPassword) return;
    setCreating(true);
    try {
      await api.createUser(newUsername, newPassword, newRole);
      addToast(`User "${newUsername}" created`, 'success');
      setNewUsername(''); setNewPassword(''); setNewRole('viewer');
      await load();
    } catch (err: unknown) {
      addToast(`Create failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setCreating(false); }
  }

  async function handleSave(username: string) {
    setSaving(username);
    try {
      const data: { role?: string; new_password?: string } = { role: editRole[username] };
      if (editPwd[username]) data.new_password = editPwd[username];
      await api.updateUser(username, data);
      addToast(`User "${username}" updated`, 'success');
      setEditPwd((p) => ({ ...p, [username]: '' }));
      await load();
    } catch (err: unknown) {
      addToast(`Update failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setSaving(null); }
  }

  async function handleDelete(username: string) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    try {
      await api.deleteUser(username);
      addToast(`User "${username}" deleted`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Delete failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  }

  return (
    <div style={{ padding: '2rem' }}>
      {/* Page header */}
      <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.5rem' }}>
        👥 User Management
      </h1>
      <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '2rem' }}>
        Manage console operator accounts and role assignments.
      </p>

      {error && (
        <div style={{ background: '#1a0a0a', border: '1px solid #7f1d1d', borderRadius: '8px', color: '#ef4444', padding: '0.75rem 1rem', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
          ⚠️ {error}
        </div>
      )}

      {/* ── Add User ──────────────────────────────────────────────────────── */}
      <div style={{ ...card, maxWidth: '520px', marginBottom: '2rem' }}>
        <form onSubmit={handleCreate}>
          <div style={{ ...sectionHead, marginTop: 0 }}>New account</div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={label}>Username</label>
            <input
              style={input}
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="e.g. alice"
              required
              autoComplete="off"
            />
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={label}>Password</label>
            <input
              style={input}
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              required
              autoComplete="new-password"
            />
          </div>

          <div style={{ marginBottom: '1.75rem' }}>
            <label style={label}>Role</label>
            <select
              style={{ ...input, cursor: 'pointer' }}
              value={newRole}
              onChange={(e) => setNewRole(e.target.value as Role)}
            >
              {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
            </select>
          </div>

          <button type="submit" disabled={creating} style={primaryBtn(creating)}>
            {creating ? 'Creating…' : '+ Create user'}
          </button>
        </form>
      </div>

      {/* ── User list ─────────────────────────────────────────────────────── */}
      <div style={{ ...sectionHead, marginTop: 0, maxWidth: '760px' }}>
        Existing accounts
      </div>

      {loading ? (
        <p style={{ color: '#475569', fontStyle: 'italic' }}>Loading…</p>
      ) : users.length === 0 ? (
        <p style={{ color: '#475569', fontStyle: 'italic' }}>No users found.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: '760px' }}>
          {users.map((u) => (
            <div key={u.username} style={card}>
              {/* User header row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
                <div style={{
                  width: '2.25rem', height: '2.25rem', borderRadius: '50%',
                  background: '#0f172a', border: '2px solid #334155',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '0.9rem', fontWeight: 700, color: '#94a3b8',
                  flexShrink: 0,
                }}>
                  {u.username.charAt(0).toUpperCase()}
                </div>
                <div>
                  <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>
                    {u.username}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.1rem' }}>
                    Since {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </div>
                </div>
                <span style={{
                  marginLeft: 'auto',
                  background: `${ROLE_COLOR[u.role] ?? '#64748b'}22`,
                  color: ROLE_COLOR[u.role] ?? '#64748b',
                  border: `1px solid ${ROLE_COLOR[u.role] ?? '#64748b'}55`,
                  borderRadius: '6px',
                  padding: '0.2rem 0.65rem',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}>
                  {u.role}
                </span>
              </div>

              {/* Edit fields */}
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <div style={{ flex: 1, minWidth: '140px' }}>
                  <label style={label}>Role</label>
                  <select
                    style={{ ...input, cursor: 'pointer', fontSize: '0.875rem', padding: '0.5rem 0.75rem' }}
                    value={editRole[u.username] ?? u.role}
                    onChange={(e) => setEditRole((p) => ({ ...p, [u.username]: e.target.value as Role }))}
                  >
                    {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
                  </select>
                </div>
                <div style={{ flex: 2, minWidth: '200px' }}>
                  <label style={label}>New password</label>
                  <input
                    style={{ ...input, fontSize: '0.875rem', padding: '0.5rem 0.75rem' }}
                    type="password"
                    placeholder="Leave blank to keep current"
                    value={editPwd[u.username] ?? ''}
                    onChange={(e) => setEditPwd((p) => ({ ...p, [u.username]: e.target.value }))}
                    autoComplete="new-password"
                  />
                </div>
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', gap: '0.625rem' }}>
                <button
                  disabled={saving === u.username}
                  onClick={() => handleSave(u.username)}
                  style={primaryBtn(saving === u.username)}
                >
                  {saving === u.username ? 'Saving…' : 'Save changes'}
                </button>
                <button
                  onClick={() => handleDelete(u.username)}
                  style={dangerBtn()}
                >
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
