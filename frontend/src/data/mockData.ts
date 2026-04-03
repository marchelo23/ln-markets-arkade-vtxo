// Mock data representing verification pipeline results
// Mirrors the structures from vtxoDAGVerification.ts

export interface MockDAGNode {
  txid: string;
  type: 'COMMITMENT' | 'TREE' | 'ARK' | 'CHECKPOINT';
  amount: number;
  status: 'valid' | 'timelock' | 'invalid';
  depth: number;
  inputs: { txid: string; vout: number }[];
  outputs: { amount: number; script: string }[];
  signature: {
    internalKey: string;
    tweakedKey: string;
    sighashType: string;
    valid: boolean;
  };
  timelock?: {
    nLockTime: number;
    nSequence: string;
    csvValues: number[];
    cltvValues: number[];
  };
  children: string[];
}

export interface MockVerificationResult {
  valid: boolean;
  vtxoRootTxid: string;
  commitmentTxid: string;
  anchoringLeafTxid: string;
  dagNodes: MockDAGNode[];
  diagnostics: DiagnosticLine[];
  stats: {
    totalNodes: number;
    signaturesVerified: number;
    timelockChecks: number;
    hashPreimageChecks: number;
    verificationTimeMs: number;
    dagDepth: number;
  };
  exitSequence: ExitTx[];
}

export interface DiagnosticLine {
  timestamp: string;
  message: string;
  type: 'success' | 'info' | 'warn' | 'error' | 'header';
}

export interface ExitTx {
  index: number;
  txid: string;
  hex: string;
  label: string;
}

// ─── Generate realistic-looking hex strings ───────────────────────────────────

function fakeHex(length: number, seed: number): string {
  const chars = '0123456789abcdef';
  let result = '';
  let s = seed;
  for (let i = 0; i < length; i++) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    result += chars[s % 16];
  }
  return result;
}

function fakeTxid(seed: number): string {
  return fakeHex(64, seed);
}

function fakeKey(seed: number): string {
  return fakeHex(64, seed * 31);
}

function fakeScript(seed: number): string {
  return '5120' + fakeHex(64, seed * 17);
}

// ─── Mock DAG Nodes ───────────────────────────────────────────────────────────

const COMMITMENT_TXID = fakeTxid(100);
const TREE_NODE_1_TXID = fakeTxid(201);
const TREE_NODE_2_TXID = fakeTxid(202);
const CHECKPOINT_TXID = fakeTxid(301);
const VTXO_LEAF_1_TXID = fakeTxid(401);
const VTXO_LEAF_2_TXID = fakeTxid(402);

export const mockNodes: MockDAGNode[] = [
  {
    txid: COMMITMENT_TXID,
    type: 'COMMITMENT',
    amount: 1000000,
    status: 'valid',
    depth: 0,
    inputs: [{ txid: fakeHex(64, 999), vout: 0 }],
    outputs: [
      { amount: 500000, script: fakeScript(1) },
      { amount: 500000, script: fakeScript(2) },
    ],
    signature: {
      internalKey: fakeKey(10),
      tweakedKey: fakeKey(11),
      sighashType: 'SIGHASH_DEFAULT (0x00)',
      valid: true,
    },
    children: [TREE_NODE_1_TXID, TREE_NODE_2_TXID],
  },
  {
    txid: TREE_NODE_1_TXID,
    type: 'TREE',
    amount: 500000,
    status: 'valid',
    depth: 1,
    inputs: [{ txid: COMMITMENT_TXID, vout: 0 }],
    outputs: [
      { amount: 250000, script: fakeScript(3) },
      { amount: 250000, script: fakeScript(4) },
    ],
    signature: {
      internalKey: fakeKey(20),
      tweakedKey: fakeKey(21),
      sighashType: 'SIGHASH_DEFAULT (0x00)',
      valid: true,
    },
    timelock: {
      nLockTime: 0,
      nSequence: '0xffffffff',
      csvValues: [144],
      cltvValues: [],
    },
    children: [CHECKPOINT_TXID, VTXO_LEAF_2_TXID],
  },
  {
    txid: TREE_NODE_2_TXID,
    type: 'TREE',
    amount: 500000,
    status: 'valid',
    depth: 1,
    inputs: [{ txid: COMMITMENT_TXID, vout: 1 }],
    outputs: [{ amount: 500000, script: fakeScript(5) }],
    signature: {
      internalKey: fakeKey(30),
      tweakedKey: fakeKey(31),
      sighashType: 'SIGHASH_DEFAULT (0x00)',
      valid: true,
    },
    children: [],
  },
  {
    txid: CHECKPOINT_TXID,
    type: 'CHECKPOINT',
    amount: 250000,
    status: 'timelock',
    depth: 2,
    inputs: [{ txid: TREE_NODE_1_TXID, vout: 0 }],
    outputs: [{ amount: 250000, script: fakeScript(6) }],
    signature: {
      internalKey: fakeKey(40),
      tweakedKey: fakeKey(41),
      sighashType: 'SIGHASH_DEFAULT (0x00)',
      valid: true,
    },
    timelock: {
      nLockTime: 0,
      nSequence: '0x00000090',
      csvValues: [144],
      cltvValues: [],
    },
    children: [VTXO_LEAF_1_TXID],
  },
  {
    txid: VTXO_LEAF_1_TXID,
    type: 'ARK',
    amount: 250000,
    status: 'valid',
    depth: 3,
    inputs: [{ txid: CHECKPOINT_TXID, vout: 0 }],
    outputs: [{ amount: 250000, script: fakeScript(7) }],
    signature: {
      internalKey: fakeKey(50),
      tweakedKey: fakeKey(51),
      sighashType: 'SIGHASH_DEFAULT (0x00)',
      valid: true,
    },
    timelock: {
      nLockTime: 0,
      nSequence: '0xffffffff',
      csvValues: [],
      cltvValues: [],
    },
    children: [],
  },
  {
    txid: VTXO_LEAF_2_TXID,
    type: 'ARK',
    amount: 250000,
    status: 'valid',
    depth: 2,
    inputs: [{ txid: TREE_NODE_1_TXID, vout: 1 }],
    outputs: [{ amount: 250000, script: fakeScript(8) }],
    signature: {
      internalKey: fakeKey(60),
      tweakedKey: fakeKey(61),
      sighashType: 'SIGHASH_ALL (0x01)',
      valid: true,
    },
    children: [],
  },
];

// ─── Diagnostics (simulated pipeline output) ─────────────────────────────────

export const mockDiagnostics: DiagnosticLine[] = [
  { timestamp: '00:00.000', message: '════════════════════════════════════════════════════════════════', type: 'header' },
  { timestamp: '00:00.001', message: '  THE SENTINEL PROTOCOL // CHELO VERIFICATION ENGINE (CVE)  ', type: 'header' },
  { timestamp: '00:00.002', message: '════════════════════════════════════════════════════════════════', type: 'header' },
  { timestamp: '00:00.010', message: '', type: 'info' },
  { timestamp: '00:00.050', message: `[1/6] Fetching VTXO chain for ${VTXO_LEAF_1_TXID.slice(0, 16)}...`, type: 'info' },
  { timestamp: '00:00.120', message: `  → Privacy mode: fetching all chains in batch`, type: 'info' },
  { timestamp: '00:00.340', message: `  → Identified local chain with 6 links (Privacy preserved)`, type: 'success' },
  { timestamp: '00:00.341', message: '', type: 'info' },
  { timestamp: '00:00.350', message: `[2/6] Separating commitment from virtual transactions`, type: 'info' },
  { timestamp: '00:00.380', message: `  → Commitment: ${COMMITMENT_TXID.slice(0, 16)}...`, type: 'info' },
  { timestamp: '00:00.400', message: `  → Virtual transactions: 5`, type: 'success' },
  { timestamp: '00:00.401', message: '', type: 'info' },
  { timestamp: '00:00.410', message: `[3/6] Fetching virtual transaction PSBTs from ASP`, type: 'info' },
  { timestamp: '00:00.850', message: `  → Decoded 5 PSBTs (batch fetch in 440ms)`, type: 'success' },
  { timestamp: '00:00.870', message: `  → All TXID computations verified (0 mismatches)`, type: 'success' },
  { timestamp: '00:00.871', message: '', type: 'info' },
  { timestamp: '00:00.880', message: `[4/6] Reconstructing DAG structure`, type: 'info' },
  { timestamp: '00:00.910', message: `  → Ouroboros cycle check: CLEAN`, type: 'success' },
  { timestamp: '00:00.930', message: `  → Orphan detection: 0 orphans (all reachable)`, type: 'success' },
  { timestamp: '00:00.950', message: `  → DAG depth: 4 levels (Commitment → VTXO Leaf)`, type: 'success' },
  { timestamp: '00:00.960', message: `  → Checkpoint detected at depth 2: ${CHECKPOINT_TXID.slice(0, 16)}...`, type: 'info' },
  { timestamp: '00:00.961', message: '', type: 'info' },
  { timestamp: '00:01.000', message: `[5/6] Cryptographic Verification`, type: 'info' },
  { timestamp: '00:01.100', message: `  → Signature ${TREE_NODE_1_TXID.slice(0, 12)}... BIP340 Schnorr: VALID ✓`, type: 'success' },
  { timestamp: '00:01.200', message: `  → Signature ${TREE_NODE_2_TXID.slice(0, 12)}... BIP340 Schnorr: VALID ✓`, type: 'success' },
  { timestamp: '00:01.300', message: `  → Signature ${CHECKPOINT_TXID.slice(0, 12)}... BIP340 Schnorr: VALID ✓`, type: 'success' },
  { timestamp: '00:01.400', message: `  → Signature ${VTXO_LEAF_1_TXID.slice(0, 12)}... BIP340 Schnorr: VALID ✓`, type: 'success' },
  { timestamp: '00:01.500', message: `  → Signature ${VTXO_LEAF_2_TXID.slice(0, 12)}... BIP340 Schnorr: VALID ✓`, type: 'success' },
  { timestamp: '00:01.550', message: `  → Taproot Merkle proofs: 5/5 verified`, type: 'success' },
  { timestamp: '00:01.600', message: `  → Sighash compliance: SIGHASH_DEFAULT/ALL only`, type: 'success' },
  { timestamp: '00:01.601', message: '', type: 'info' },
  { timestamp: '00:01.610', message: `[6/6] On-chain Anchoring Verification`, type: 'info' },
  { timestamp: '00:01.700', message: `  → Commitment ${COMMITMENT_TXID.slice(0, 16)}... CONFIRMED`, type: 'success' },
  { timestamp: '00:01.750', message: `  → Confirmation depth: 142 blocks`, type: 'success' },
  { timestamp: '00:01.800', message: `  → Output script match: VERIFIED`, type: 'success' },
  { timestamp: '00:01.850', message: `  → Output amount match: 1,000,000 sats`, type: 'success' },
  { timestamp: '00:01.851', message: '', type: 'info' },
  { timestamp: '00:01.900', message: `══════════════════════════════════════════════`, type: 'header' },
  { timestamp: '00:01.901', message: `  RESULT: ALL VERIFICATIONS PASSED ✓`, type: 'success' },
  { timestamp: '00:01.902', message: `  Pipeline complete in 1.902 seconds`, type: 'success' },
  { timestamp: '00:01.903', message: `══════════════════════════════════════════════`, type: 'header' },
];

// ─── Exit Sequence ────────────────────────────────────────────────────────────

export const mockExitSequence: ExitTx[] = [
  {
    index: 0,
    txid: TREE_NODE_1_TXID,
    hex: '02000000' + fakeHex(400, 5001),
    label: 'Anchor Tx (spends commitment output)',
  },
  {
    index: 1,
    txid: CHECKPOINT_TXID,
    hex: '02000000' + fakeHex(350, 5002),
    label: 'Checkpoint (sweep delay: 144 blocks)',
  },
  {
    index: 2,
    txid: VTXO_LEAF_1_TXID,
    hex: '02000000' + fakeHex(300, 5003),
    label: 'VTXO Leaf (final claim transaction)',
  },
];

// ─── Combined Result ──────────────────────────────────────────────────────────

export const mockResult: MockVerificationResult = {
  valid: true,
  vtxoRootTxid: VTXO_LEAF_1_TXID,
  commitmentTxid: COMMITMENT_TXID,
  anchoringLeafTxid: TREE_NODE_1_TXID,
  dagNodes: mockNodes,
  diagnostics: mockDiagnostics,
  stats: {
    totalNodes: 6,
    signaturesVerified: 5,
    timelockChecks: 4,
    hashPreimageChecks: 1,
    verificationTimeMs: 1902,
    dagDepth: 4,
  },
  exitSequence: mockExitSequence,
};
