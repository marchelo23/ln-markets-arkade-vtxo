import { useState } from 'react';
import { mockResult } from './data/mockData.ts';
import Dashboard from './views/Dashboard.tsx';
import DAGExplorer from './views/DAGExplorer.tsx';
import SignatureAudit from './views/SignatureAudit.tsx';
import SovereignExit from './views/SovereignExit.tsx';
import LiveTerminal from './views/LiveTerminal.tsx';

type View = 'dashboard' | 'dag' | 'signatures' | 'exit' | 'terminal';

const NAV_ITEMS: { id: View; label: string; icon: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '◈' },
  { id: 'dag', label: 'DAG Explorer', icon: '⬡' },
  { id: 'signatures', label: 'Signatures', icon: '⚿' },
  { id: 'exit', label: 'Sovereign Exit', icon: '⇪' },
  { id: 'terminal', label: 'Terminal', icon: '▸' },
];

const VIEW_TITLES: Record<View, string> = {
  dashboard: 'Command Center',
  dag: 'DAG Explorer // Structural Analysis',
  signatures: 'Signature Verification Audit',
  exit: 'Tier 3 // Sovereign Unilateral Exit',
  terminal: 'Live Verification Terminal',
};

export default function App() {
  const [activeView, setActiveView] = useState<View>('dashboard');

  return (
    <div className="app-layout">
      {/* ── Sidebar ──────────────────────────────────── */}
      <nav className="app-sidebar">
        <div className="sidebar-logo">
          <h1>SENTINEL</h1>
          <span>Powered by CVE</span>
          <span style={{ fontSize: '0.55rem' }}>(Chelo Verification Engine)</span>
        </div>

        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            id={`nav-${item.id}`}
            className={`nav-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => setActiveView(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}

        <div style={{ flex: 1 }} />

        <div style={{ 
          padding: '12px', 
          background: 'var(--surface-container)',
          borderRadius: '2px',
        }}>
          <div className="label-md" style={{ color: 'var(--on-surface-dim)', marginBottom: '4px' }}>
            STATUS
          </div>
          <div className="mono" style={{ 
            color: mockResult.valid ? 'var(--primary)' : 'var(--tertiary)',
            fontWeight: 700,
          }}>
            {mockResult.valid ? '● VERIFIED' : '● FAILED'}
          </div>
          <div className="mono-sm" style={{ color: 'var(--on-surface-dim)', marginTop: '4px' }}>
            {mockResult.stats.totalNodes} nodes
          </div>
          <div className="mono-sm" style={{ color: 'var(--on-surface-dim)' }}>
            {mockResult.stats.signaturesVerified} sigs
          </div>
          <div className="mono-sm" style={{ color: 'var(--on-surface-dim)' }}>
            101 tests ✓
          </div>
        </div>
      </nav>

      {/* ── Main Content ─────────────────────────────── */}
      <main className="app-main">
        <header className="app-topbar">
          <span className="topbar-title">{VIEW_TITLES[activeView]}</span>
          <div className="topbar-status">
            <div className="topbar-indicator">
              <span className="topbar-dot" />
              <span style={{ color: 'var(--on-surface-variant)' }}>
                PIPELINE OK
              </span>
            </div>
            <div className="topbar-indicator">
              <span className="topbar-dot" />
              <span style={{ color: 'var(--on-surface-variant)' }}>
                ANCHORED
              </span>
            </div>
            <div className="topbar-indicator">
              <span className="topbar-dot warning" />
              <span style={{ color: 'var(--on-surface-variant)' }}>
                CSV 144
              </span>
            </div>
          </div>
        </header>

        <div className="app-content">
          {activeView === 'dashboard' && <Dashboard data={mockResult} />}
          {activeView === 'dag' && <DAGExplorer nodes={mockResult.dagNodes} />}
          {activeView === 'signatures' && <SignatureAudit nodes={mockResult.dagNodes} />}
          {activeView === 'exit' && <SovereignExit sequence={mockResult.exitSequence} />}
          {activeView === 'terminal' && <LiveTerminal lines={mockResult.diagnostics} />}
        </div>
      </main>
    </div>
  );
}
