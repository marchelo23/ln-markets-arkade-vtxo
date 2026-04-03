import { useState } from 'react';
import type { MockDAGNode } from '../data/mockData';

interface Props {
  nodes: MockDAGNode[];
}

function truncTxid(txid: string): string {
  return txid.slice(0, 8) + '...' + txid.slice(-8);
}

function formatSats(sats: number): string {
  return sats.toLocaleString() + ' sats';
}

const TYPE_LABELS: Record<string, string> = {
  COMMITMENT: '◆ COMMITMENT (ON-CHAIN)',
  TREE: '⬡ TREE NODE',
  ARK: '◈ VTXO LEAF',
  CHECKPOINT: '⏱ CHECKPOINT',
};

export default function DAGExplorer({ nodes }: Props) {
  const [selectedTxid, setSelectedTxid] = useState<string | null>(null);
  const selected = nodes.find((n) => n.txid === selectedTxid);

  // Sort by depth for rendering
  const sorted = [...nodes].sort((a, b) => a.depth - b.depth);

  return (
    <div className="dag-container">
      {/* ── Tree View ──────────────────────────────────── */}
      <div className="dag-tree">
        {sorted.map((node, i) => (
          <div key={node.txid}>
            {i > 0 && (
              <>
                <div className="dag-connector" />
                <div className="dag-connector-label">
                  input[0] → vout:{node.inputs[0]?.vout ?? 0}
                </div>
                <div className="dag-connector" />
              </>
            )}
            <div
              className={`dag-node ${selectedTxid === node.txid ? 'selected' : ''}`}
              onClick={() => setSelectedTxid(node.txid)}
              id={`dag-node-${node.txid.slice(0, 8)}`}
            >
              <div className={`dag-node-status-bar ${node.status}`} />
              <div className="dag-node-content">
                <div className="dag-node-type">
                  {TYPE_LABELS[node.type] || node.type}
                </div>
                <div className="dag-node-txid">{truncTxid(node.txid)}</div>
                <div className="dag-node-amount">{formatSats(node.amount)}</div>
              </div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '0 16px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.65rem',
                  color: 'var(--on-surface-dim)',
                }}
              >
                DEPTH {node.depth}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Detail Panel ───────────────────────────────── */}
      <div className="dag-detail">
        {selected ? (
          <>
            <div className="detail-section">
              <div className="detail-section-title">Transaction Info</div>
              <div className="detail-row">
                <span className="detail-key">TXID</span>
                <span className="detail-value mono" title={selected.txid}>
                  {truncTxid(selected.txid)}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Type</span>
                <span className="detail-value">{selected.type}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Amount</span>
                <span className="detail-value mono status-valid">
                  {formatSats(selected.amount)}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Depth</span>
                <span className="detail-value mono">{selected.depth}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Status</span>
                <span className={`detail-value status-${selected.status}`}>
                  {selected.status.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="detail-section">
              <div className="detail-section-title">Signature</div>
              <div className="detail-row">
                <span className="detail-key">Internal Key</span>
                <span className="detail-value mono" title={selected.signature.internalKey}>
                  {selected.signature.internalKey.slice(0, 16)}...
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Tweaked Key</span>
                <span className="detail-value mono" title={selected.signature.tweakedKey}>
                  {selected.signature.tweakedKey.slice(0, 16)}...
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Sighash</span>
                <span className="detail-value mono">
                  {selected.signature.sighashType}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Valid</span>
                <span className={`detail-value ${selected.signature.valid ? 'status-valid' : 'status-invalid'}`}>
                  {selected.signature.valid ? '✓ VERIFIED' : '✗ INVALID'}
                </span>
              </div>
            </div>

            {selected.inputs.length > 0 && (
              <div className="detail-section">
                <div className="detail-section-title">Inputs</div>
                {selected.inputs.map((inp, i) => (
                  <div className="detail-row" key={i}>
                    <span className="detail-key">IN[{i}]</span>
                    <span className="detail-value mono" title={inp.txid}>
                      {truncTxid(inp.txid)}:{inp.vout}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {selected.outputs.length > 0 && (
              <div className="detail-section">
                <div className="detail-section-title">Outputs</div>
                {selected.outputs.map((out, i) => (
                  <div key={i}>
                    <div className="detail-row">
                      <span className="detail-key">OUT[{i}]</span>
                      <span className="detail-value mono status-valid">
                        {formatSats(out.amount)}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-key">Script</span>
                      <span className="detail-value mono" title={out.script}>
                        {out.script.slice(0, 20)}...
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {selected.timelock && (
              <div className="detail-section">
                <div className="detail-section-title">Timelocks</div>
                <div className="detail-row">
                  <span className="detail-key">nLockTime</span>
                  <span className="detail-value mono">{selected.timelock.nLockTime}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-key">nSequence</span>
                  <span className="detail-value mono">{selected.timelock.nSequence}</span>
                </div>
                {selected.timelock.csvValues.length > 0 && (
                  <div className="detail-row">
                    <span className="detail-key">CSV</span>
                    <span className="detail-value mono status-warning">
                      {selected.timelock.csvValues.join(', ')} blocks
                    </span>
                  </div>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">
            <div className="empty-state-icon">⬡</div>
            <div className="label-md" style={{ color: 'var(--on-surface-dim)' }}>
              SELECT A NODE
            </div>
            <div className="body-md" style={{ color: 'var(--on-surface-dim)' }}>
              Click on any DAG node to inspect its transaction details, signature, and timelock constraints.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
