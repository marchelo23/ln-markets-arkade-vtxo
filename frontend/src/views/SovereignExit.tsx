import type { ExitTx } from '../data/mockData';

interface Props {
  sequence: ExitTx[];
}

export default function SovereignExit({ sequence }: Props) {
  return (
    <div className="exit-container animate-fade-in">
      <div className="exit-sequence">
        <div style={{ marginBottom: '24px' }}>
          <h2 className="display-sm" style={{ marginBottom: '8px' }}>
            Unilateral Exit Sequence
          </h2>
          <p className="body-md" style={{ color: 'var(--on-surface-variant)' }}>
            This sequence of pre-signed virtual transactions must be broadcast to the Bitcoin network in exact order to unilaterally exit the Ark pool without ASP cooperation.
          </p>
        </div>

        {sequence.map((tx, i) => (
          <div
            key={tx.txid}
            className="exit-tx"
            style={{ animationDelay: `${i * 0.15}s` }}
          >
            <div className="exit-tx-index">{tx.index + 1}</div>
            <div className="exit-tx-content">
              <div className="exit-tx-label">{tx.label}</div>
              <div className="exit-tx-hex">{tx.hex}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="exit-sidebar">
        <div className="exit-info-card">
          <div className="exit-lock-icon">🔒</div>
          <h3 className="label-lg" style={{ textAlign: 'center', marginBottom: '16px' }}>
            SECURE STORAGE
          </h3>
          <div className="detail-row">
            <span className="detail-key">Algorithm</span>
            <span className="detail-value mono status-valid">AES-256-GCM</span>
          </div>
          <div className="detail-row">
            <span className="detail-key">KDF</span>
            <span className="detail-value mono status-valid">PBKDF2-SHA256</span>
          </div>
          <div className="detail-row">
            <span className="detail-key">Iterations</span>
            <span className="detail-value mono">100,000</span>
          </div>
          <div className="detail-row">
            <span className="detail-key">Status</span>
            <span className="detail-value mono status-valid">ENCRYPTED</span>
          </div>
        </div>

        <button 
          className="btn btn-panic"
          onClick={() => {
            alert('CRITICAL: Initiating Sovereign Exit. This will begin broadcasting the stored transaction sequence directly to the Bitcoin P2P network. Ensure your on-chain node is synced.');
          }}
        >
          EXECUTE EXIT
        </button>
      </div>
    </div>
  );
}
