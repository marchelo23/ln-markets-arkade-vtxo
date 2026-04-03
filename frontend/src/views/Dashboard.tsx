import type { MockVerificationResult } from '../data/mockData';

interface Props {
  data: MockVerificationResult;
}

export default function Dashboard({ data }: Props) {
  const tiers = [
    {
      label: 'Tier 1',
      title: 'Core VTXO Chain Verification',
      desc: 'DAG reconstruction, signature verification, on-chain anchoring',
      status: 'COMPLETE',
      statusColor: 'var(--primary)',
      metrics: [
        { value: data.stats.totalNodes.toString(), label: 'DAG Nodes' },
        { value: data.stats.signaturesVerified.toString(), label: 'Signatures' },
        { value: '142', label: 'Confirmations' },
      ],
    },
    {
      label: 'Tier 2',
      title: 'Full Script Satisfaction',
      desc: 'Taproot script trees, timelocks, hash preimage verification (Boltz)',
      status: 'COMPLETE',
      statusColor: 'var(--primary)',
      metrics: [
        { value: data.stats.timelockChecks.toString(), label: 'Timelock Checks' },
        { value: data.stats.hashPreimageChecks.toString(), label: 'HTLC Verified' },
        { value: '5', label: 'Merkle Proofs' },
      ],
    },
    {
      label: 'Tier 3',
      title: 'Sovereign Unilateral Exit',
      desc: 'Exit data extraction, AES-256-GCM storage, broadcast sequence',
      status: 'ARMED',
      statusColor: 'var(--secondary)',
      cardClass: 'warning',
      metrics: [
        { value: data.exitSequence.length.toString(), label: 'Broadcast Txs' },
        { value: 'AES-GCM', label: 'Encryption' },
        { value: 'PBKDF2', label: 'Key Derivation' },
      ],
    },
  ];

  return (
    <div>
      {/* ── Tier Cards ──────────────────────────────────── */}
      <div className="dashboard-grid">
        {tiers.map((tier, i) => (
          <div
            key={i}
            className={`tier-card ${tier.cardClass || ''} animate-fade-in`}
            style={{ animationDelay: `${i * 0.1}s` }}
          >
            <div className="tier-card-header">
              <span className="tier-card-label">{tier.label}</span>
              <span
                className="tier-card-status"
                style={{ color: tier.statusColor }}
              >
                ● {tier.status}
              </span>
            </div>
            <div className="tier-card-title">{tier.title}</div>
            <div className="tier-card-desc">{tier.desc}</div>
            <div className="tier-card-metrics">
              {tier.metrics.map((m, j) => (
                <div className="metric" key={j}>
                  <span
                    className="metric-value"
                    style={{ color: tier.statusColor }}
                  >
                    {m.value}
                  </span>
                  <span className="metric-label">{m.label}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* ── Stats Row ───────────────────────────────────── */}
      <div className="stats-row">
        <div className="stat-box animate-fade-in" style={{ animationDelay: '0.3s' }}>
          <div className="stat-value status-valid">101</div>
          <div className="stat-label">Tests Passed</div>
        </div>
        <div className="stat-box animate-fade-in" style={{ animationDelay: '0.4s' }}>
          <div className="stat-value" style={{ color: 'var(--primary)' }}>{data.stats.dagDepth}</div>
          <div className="stat-label">DAG Depth</div>
        </div>
        <div className="stat-box animate-fade-in" style={{ animationDelay: '0.5s' }}>
          <div className="stat-value" style={{ color: 'var(--secondary)' }}>
            {data.stats.verificationTimeMs}ms
          </div>
          <div className="stat-label">Verification Time</div>
        </div>
        <div className="stat-box animate-fade-in" style={{ animationDelay: '0.6s' }}>
          <div className="stat-value status-valid">8</div>
          <div className="stat-label">Test Suites</div>
        </div>
      </div>

      {/* ── Audit Log ───────────────────────────────────── */}
      <div className="audit-log animate-fade-in" style={{ animationDelay: '0.7s' }}>
        <div className="audit-log-header">
          <span className="label-md" style={{ color: 'var(--on-surface-dim)' }}>
            VERIFICATION PIPELINE LOG
          </span>
          <span className="mono-sm status-dim">
            {data.diagnostics.length} entries
          </span>
        </div>
        {data.diagnostics.map((line, i) => (
          <div key={i} className={`audit-log-line ${line.type}`}>
            <span className="timestamp">[{line.timestamp}]</span>
            {line.message}
          </div>
        ))}
      </div>
    </div>
  );
}
