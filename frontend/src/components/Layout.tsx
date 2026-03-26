import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import './Layout.css';

const ROLE_ORDER: Record<string, number> = {
  viewer: 0, analyst: 1, operator: 2, admin: 3,
};

interface NavItem {
  to: string;
  icon: string;
  label: string;
  end?: boolean;
  minRole?: string;
}

interface NavGroup {
  heading: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    heading: 'Overview',
    items: [
      { to: '/', icon: '⚡', label: 'Dashboard', end: true },
      { to: '/events', icon: '📡', label: 'Events' },
      { to: '/incidents', icon: '🚨', label: 'Incidents' },
      { to: '/audit', icon: '📋', label: 'Audit Log' },
    ],
  },
  {
    heading: 'Sensors',
    items: [
      { to: '/sensors', icon: '🔬', label: 'Sensors' },
    ],
  },
  {
    heading: 'Domains',
    items: [
      { to: '/hostguard', icon: '🖥️', label: 'HostGuard' },
      { to: '/networkguard', icon: '🌐', label: 'NetworkGuard' },
      { to: '/commsguard', icon: '💬', label: 'CommsGuard' },
      { to: '/agentguard', icon: '🤖', label: 'AgentGuard' },
      { to: '/modelguard', icon: '🧠', label: 'ModelGuard' },
      { to: '/supplychain', icon: '📦', label: 'Supply Chain' },
    ],
  },
  {
    heading: 'Settings',
    items: [
      { to: '/webhooks', icon: '🔔', label: 'Webhooks', minRole: 'operator' },
      { to: '/users', icon: '👥', label: 'Users', minRole: 'admin' },
      { to: '/account', icon: '👤', label: 'Account' },
    ],
  },
];

export default function Layout() {
  const { logout, role } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate('/login');
  }

  const userRank = ROLE_ORDER[role] ?? -1;

  const visibleGroups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter(
      (item) => !item.minRole || userRank >= (ROLE_ORDER[item.minRole] ?? 0),
    ),
  })).filter((group) => group.items.length > 0);

  return (
    <div className="layout">
      <aside className="sidebar">
        {/* Brand */}
        <div className="sidebar-brand">
          <span className="sidebar-logo">⚔️</span>
          <div className="sidebar-brand-text">
            <span className="sidebar-title">OpenGuard</span>
            <span className="sidebar-version">v5</span>
          </div>
        </div>

        {/* Navigation groups */}
        <nav className="sidebar-nav">
          {visibleGroups.map((group, gi) => (
            <div key={group.heading} className="nav-group">
              {gi > 0 && <div className="nav-divider" />}
              <span className="nav-group-label">{group.heading}</span>
              {group.items.map(({ to, icon, label, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    `sidebar-link${isActive ? ' sidebar-link--active' : ''}`
                  }
                >
                  <span className="sidebar-link-icon">{icon}</span>
                  <span className="sidebar-link-label">{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Footer */}
        <div className="sidebar-footer">
          <div className="sidebar-user">
            <span className="sidebar-user-avatar">👤</span>
            <span className="sidebar-user-badge">{role || 'viewer'}</span>
          </div>
          <button className="logout-btn" onClick={handleLogout}>
            <span className="sidebar-link-icon">🚪</span>
            <span>Logout</span>
          </button>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
}
