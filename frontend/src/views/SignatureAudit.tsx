import { useState } from 'react';
import type { MockDAGNode } from '../data/mockData';

interface Props {
  nodes: MockDAGNode[];
}

export default function SignatureAudit({ nodes }: Props) {
  const [expandedRow, setExpandedRow] = useState<string | null>(null);

  // Filter out nodes that don't have signatures (e.g. some root references if we had them)
  const sigNodes = nodes.filter((n) => n.signature);

  return (
    <div>
      <div className="sig-table animate-fade-in">
        <div className="sig-table-header">
          <span>TXID</span>
          <span>INTERNAL KEY</span>
          <span>TWEAKED KEY</span>
          <span>SIGHASH</span>
          <span>STATUS</span>
        </div>

        {sigNodes.map((node, i) => {
          const isExpanded = expandedRow === node.txid;
          return (
            <div key={node.txid}>
              <div
                className="sig-row"
                onClick={() => setExpandedRow(isExpanded ? null : node.txid)}
                style={{ animationDelay: `${i * 0.05}s` }}
              >
                <span>{node.txid}</span>
                <span title={node.signature.internalKey}>{node.signature.internalKey}</span>
                <span title={node.signature.tweakedKey}>{node.signature.tweakedKey}</span>
                <span>{node.signature.sighashType}</span>
                <span
                  className={
                    node.signature.valid ? 'sig-status valid' : 'sig-status invalid'
                  }
                >
                  {node.signature.valid ? 'VERIFIED' : 'FAILED'}
                </span>
              </div>

              {isExpanded && (
                <div className="sig-detail-expand">
                  <div style={{ marginBottom: '8px', color: 'var(--primary)' }}>
                    // SCHNORR VERIFICATION DETAILS (BIP-340 / BIP-341)
                  </div>
                  <div>Node Depth: {node.depth}</div>
                  <div>Type: {node.type}</div>
                  <div>
                    Taproot Tweak: Q = P + H(P || merkle_root)G
                  </div>
                  <div>
                    Sighash Algorithm: preimageWitnessV1()
                  </div>
                  <div
                    style={{
                      marginTop: '8px',
                      color: node.signature.valid ? 'var(--primary)' : 'var(--tertiary)',
                    }}
                  >
                    Result:{' '}
                    {node.signature.valid
                      ? 'Signature is valid against the tweaked public key.'
                      : 'Signature validation failed.'}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
