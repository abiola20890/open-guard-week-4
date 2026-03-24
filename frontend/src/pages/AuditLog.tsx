import { useEffect, useReducer, useState } from 'react';
import { api, type AuditEntry } from '../api';
import Pagination from '../components/Pagination';

const PAGE_SIZE = 100;

type FetchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; entries: AuditEntry[]; total: number }
  | { status: 'error'; error: string };

type FetchAction =
  | { type: 'loading' }
  | { type: 'success'; entries: AuditEntry[]; total: number }
  | { type: 'error'; error: string };

function fetchReducer(_: FetchState, action: FetchAction): FetchState {
  switch (action.type) {
    case 'loading': return { status: 'loading' };
    case 'success': return { status: 'success', entries: action.entries, total: action.total };
    case 'error': return { status: 'error', error: action.error };
  }
}

export default function AuditLog() {
  const [state, dispatch] = useReducer(fetchReducer, { status: 'loading' } as FetchState);
  const [filter, setFilter] = useState('');
  const [queryEventId, setQueryEventId] = useState<string | undefined>(undefined);
  const [page, setPage] = useState(1);

  useEffect(() => {
    let cancelled = false;
    dispatch({ type: 'loading' });
    api.audit(queryEventId, page)
      .then((res) => { if (!cancelled) dispatch({ type: 'success', entries: res.entries ?? [], total: res.total ?? 0 }); })
      .catch((err: unknown) => {
        if (!cancelled) dispatch({ type: 'error', error: err instanceof Error ? err.message : String(err) });
      });
    return () => { cancelled = true; };
  }, [queryEventId, page]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setQueryEventId(filter.trim() || undefined);
  }

  return (
    <div>
      <div className="page-header">
        <h2>Audit Log</h2>
        <p>Immutable SHA-256 chained audit ledger</p>
      </div>

      {state.status === 'error' && <div className="error-msg">⚠️ {state.error}</div>}

      <form onSubmit={handleSearch} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by Event ID (optional)"
          style={{
            flex: 1,
            padding: '0.5rem 0.75rem',
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '6px',
            color: '#e2e8f0',
            fontFamily: 'inherit',
            fontSize: '0.875rem',
          }}
        />
        <button
          type="submit"
          style={{ background: '#1d4ed8', color: '#fff', padding: '0.5rem 1rem', borderRadius: '6px', border: 'none' }}
        >
          Search
        </button>
        {filter && (
          <button
            type="button"
            onClick={() => { setFilter(''); setQueryEventId(undefined); }}
            style={{ background: '#334155', color: '#e2e8f0', padding: '0.5rem 1rem', borderRadius: '6px', border: 'none' }}
          >
            Clear
          </button>
        )}
      </form>

      <div className="table-card">
        <div className="table-header">
          Audit Entries — {state.status === 'success' ? state.total : 0} total
        </div>
        {state.status === 'loading' ? (
          <div className="loading">Loading…</div>
        ) : state.status !== 'success' || state.entries.length === 0 ? (
          <div className="empty-state">No audit entries found. The ledger will populate as the platform processes events and incidents.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Entry ID</th>
                <th>Event ID</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Timestamp</th>
                <th>SHA-256 Hash</th>
              </tr>
            </thead>
            <tbody>
              {state.status === 'success' && state.entries.map((entry, i) => (
                <tr key={entry.id ?? i}>
                  <td><code>{entry.id ?? '—'}</code></td>
                  <td><code>{entry.event_id ?? '—'}</code></td>
                  <td>{entry.action ?? '—'}</td>
                  <td>{entry.actor ?? '—'}</td>
                  <td>{entry.timestamp ?? '—'}</td>
                  <td>
                    <code style={{ fontSize: '0.7rem', color: '#64748b' }}>
                      {entry.hash ? `${String(entry.hash).slice(0, 16)}…` : '—'}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Pagination
        page={page}
        total={state.status === 'success' ? state.total : 0}
        pageSize={PAGE_SIZE}
        onPageChange={(p) => { setPage(p); }}
      />
    </div>
  );
}
