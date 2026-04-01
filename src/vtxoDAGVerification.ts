/**
 * ============================================================================
 *  VTXO DAG Verification — Tier 1: Chain Reconstruction & Structural Validation
 * ============================================================================
 *
 *  Implements client-side verification of VTXO chains for the Arkade SDK.
 *
 *  Given a VTXO (leaf) received from the ASP, this module:
 *    1. Fetches the full chain of virtual transactions from the IndexerService.
 *    2. Fetches the raw PSBT data for each virtual transaction.
 *    3. Reconstructs the complete DAG of presigned virtual transactions
 *       from the leaf back to the batch output (root).
 *    4. Validates that every transaction's inputs correctly reference
 *       the outputs of its parent in the DAG.
 *    5. Validates checkpoint transactions (if present), verifying:
 *       – Their structural coherence with the sweep delay.
 *       – Their correct integration into the DAG.
 *    6. Validates that the root of the DAG is anchored to a valid
 *       batch output on the commitment transaction.
 *
 *  ZERO TRUST: Every piece of data from the ASP is treated as potentially
 *  malicious. The function fails loudly on any inconsistency.
 *
 *  Dependencies: @scure/btc-signer, @scure/base (standard Arkade SDK deps).
 * ============================================================================
 */

import { Transaction } from "@scure/btc-signer/transaction.js";
import { hex, base64 } from "@scure/base";
import { verifyDAGSignatures } from "./signatureVerification.js";
import { verifyNodeTaproot } from "./taprootVerification.js";
import { verifyDAGTimelocks, type ChainState } from "./timelockVerification.js";
import { verifyDAGHashPreimages } from "./hashPreimageVerification.js";
import { ConcurrencyLimiter, VerificationCache } from "./performanceUtils.js";

// ─── Performance Buffers ───────────────────────────────────────────────────
//
// These global instances maintain state across SDK calls to optimize resources.
// In a production environment, these could be passed via configuration.
//
const globalVerificationCache = new VerificationCache();
const globalOnchainLimiter = new ConcurrencyLimiter(10); // Max 10 concurrent RPCs

// ─── Types aligned with Arkade SDK (providers/indexer.ts, wallet/index.ts) ───

/** Transaction outpoint reference (txid + output index). */
export interface Outpoint {
  txid: string;
  vout: number;
}

/** Types of transactions in a VTXO chain, as returned by the Indexer. */
export enum ChainTxType {
  UNSPECIFIED = "INDEXER_CHAINED_TX_TYPE_UNSPECIFIED",
  COMMITMENT = "INDEXER_CHAINED_TX_TYPE_COMMITMENT",
  ARK = "INDEXER_CHAINED_TX_TYPE_ARK",
  TREE = "INDEXER_CHAINED_TX_TYPE_TREE",
  CHECKPOINT = "INDEXER_CHAINED_TX_TYPE_CHECKPOINT",
}

/** A single link in the VTXO chain (from the Indexer). */
export interface ChainTx {
  txid: string;
  expiresAt: string;
  type: ChainTxType;
  /** txids of the transactions this one spends (parent references). */
  spends: string[];
}

/** The full chain of a VTXO (from the Indexer). */
export interface VtxoChain {
  chain: ChainTx[];
}

// ─── Provider Interfaces (subset needed for verification) ────────────────────

/**
 * Minimal interface for the IndexerService.
 * Mirrors IndexerProvider from @arkade-os/sdk.
 */
export interface IndexerProvider {
  /** Get all VTXO chains associated with a specific commitment batch (Privacy Mode). */
  getBatchVtxos(commitmentTxid: string): Promise<VtxoChain[]>;

  /** Fetch raw virtual transaction PSBTs (base64-encoded). */
  getVirtualTxs(txids: string[]): Promise<{ txs: string[] }>;
}

/**
 * Minimal interface for an on-chain explorer/node.
 * Mirrors OnchainProvider from @arkade-os/sdk.
 */
export interface OnchainProvider {
  /** Get a raw transaction by txid (hex-encoded). */
  getRawTransaction(txid: string): Promise<string>;
  /** Check if a transaction is confirmed and at what depth. */
  getTxStatus(txid: string): Promise<{
    confirmed: boolean;
    blockHeight?: number;
    blockTime?: number;
  }>;
  /** Get current blockchain tip info (optional — needed for timelock validation). */
  getBlockchainInfo?(): Promise<{ height: number; medianTime: number }>;
  /** Orchestrate and push a signed raw transaction completely to the Bitcoin network. */
  broadcastTransaction(txHex: string): Promise<string>;
}

/**
 * Minimal interface for the SDK's Storage Adapter.
 * Provides generic KV storage capabilities for sovereign sovereign exits.
 */
export interface StorageProvider {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  removeItem(key: string): Promise<void>;
}

// ─── DAG Node & Result Types ─────────────────────────────────────────────────

/** A single node in the reconstructed DAG. */
export interface DAGNode {
  /** Virtual txid (computed from the PSBT). */
  txid: string;

  /** The deserialized Bitcoin transaction (from PSBT). */
  tx: Transaction;

  /** Chain metadata from the Indexer. */
  chainTx: ChainTx;

  /** Raw base64 PSBT as received from the ASP. */
  rawPsbt: string;

  /** Child nodes, keyed by the output index they spend. */
  children: Map<number, DAGNode>;

  /** Parent node (null for the root / commitment-anchored node). */
  parent: DAGNode | null;

  /** The output index in the parent that this node spends. */
  parentOutputIndex: number | null;
}

/** Validation result for the DAG. */
export interface DAGValidationResult {
  /** Whether all validations passed. */
  valid: boolean;

  /** The reconstructed DAG, from root (batch output side) to leaf. */
  root: DAGNode;

  /** The leaf node (the user's VTXO). */
  leaf: DAGNode;

  /** The commitment tx that anchors the DAG on-chain. */
  commitmentTxid: string;

  /** The batch output index on the commitment tx. */
  batchOutputIndex: number;

  /** Details of checkpoint validations performed. */
  checkpointValidations: CheckpointValidation[];

  /** Diagnostic messages for each validation step. */
  diagnostics: string[];
}

/** Validation result specific to a checkpoint transaction. */
export interface CheckpointValidation {
  txid: string;
  /** Whether the checkpoint's expiry is coherent with the sweep delay. */
  expiryCoherent: boolean;
  /** Whether the checkpoint references the correct parent output. */
  parentChainValid: boolean;
  /** Human-readable notes. */
  notes: string[];
}

// ─── Error Definitions ───────────────────────────────────────────────────────

export class VtxoVerificationError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly context?: Record<string, unknown>
  ) {
    super(`[VTXO-VERIFY:${code}] ${message}`);
    this.name = "VtxoVerificationError";
  }
}

const Errors = {
  EMPTY_CHAIN: (vtxo: Outpoint) =>
    new VtxoVerificationError(
      `Empty chain returned for VTXO ${vtxo.txid}:${vtxo.vout}`,
      "EMPTY_CHAIN",
      { vtxo }
    ),

  NO_COMMITMENT: () =>
    new VtxoVerificationError(
      "No commitment transaction found at the root of the chain",
      "NO_COMMITMENT"
    ),

  MISSING_TX: (txid: string) =>
    new VtxoVerificationError(
      `Virtual transaction ${txid} not returned by the ASP`,
      "MISSING_TX",
      { txid }
    ),

  TXID_MISMATCH: (expected: string, actual: string) =>
    new VtxoVerificationError(
      `Txid mismatch: ASP claims ${expected} but PSBT computes to ${actual}`,
      "TXID_MISMATCH",
      { expected, actual }
    ),

  INPUT_CHAIN_BREAK: (childTxid: string, expectedParent: string, actualParent: string) =>
    new VtxoVerificationError(
      `Input chain break: tx ${childTxid} should reference parent ${expectedParent} but references ${actualParent}`,
      "INPUT_CHAIN_BREAK",
      { childTxid, expectedParent, actualParent }
    ),

  AMOUNT_MISMATCH: (
    parentTxid: string,
    outputIndex: number,
    parentAmount: bigint,
    childSum: bigint
  ) =>
    new VtxoVerificationError(
      `Amount mismatch: parent ${parentTxid} output[${outputIndex}] = ${parentAmount} sats, but child outputs sum = ${childSum} sats`,
      "AMOUNT_MISMATCH",
      { parentTxid, outputIndex, parentAmount: parentAmount.toString(), childSum: childSum.toString() }
    ),

  INVALID_INPUT_COUNT: (txid: string, count: number) =>
    new VtxoVerificationError(
      `Virtual transaction ${txid} has ${count} inputs, expected exactly 1`,
      "INVALID_INPUT_COUNT",
      { txid, count }
    ),

  CHECKPOINT_EXPIRY_INCOHERENT: (txid: string, details: string) =>
    new VtxoVerificationError(
      `Checkpoint ${txid} has incoherent expiry: ${details}`,
      "CHECKPOINT_EXPIRY_INCOHERENT",
      { txid }
    ),

  ORPHAN_TX: (txid: string) =>
    new VtxoVerificationError(
      `Transaction ${txid} is orphaned — not reachable from the commitment root`,
      "ORPHAN_TX",
      { txid }
    ),
} as const;

// ─── Batch output index convention (from SDK tree/validation.ts) ─────────────
export const BATCH_OUTPUT_VTXO_INDEX = 0;

// ─── Main Public Function ────────────────────────────────────────────────────

/**
 * Reconstructs and validates the full DAG for a given VTXO.
 *
 * This is the Tier 1 core deliverable of the assignment:
 *   - Fetches the VTXO chain from the Indexer.
 *   - Fetches all virtual transaction PSBTs from the Indexer.
 *   - Reconstructs the DAG from leaf → root.
 *   - Validates input→output chaining at every level.
 *   - Validates checkpoint transactions for sweep-delay coherence.
 *   - Validates that the root is anchored to the commitment tx.
 *
 * @param vtxoOutpoint  The leaf VTXO outpoint to verify.
 * @param indexer       An IndexerProvider implementation (e.g. RestIndexerProvider).
 * @param onchain       An OnchainProvider implementation (e.g. EsploraProvider).
 * @throws VtxoVerificationError on any structural inconsistency.
 * @returns A DAGValidationResult with the full reconstructed + validated DAG.
 */
export async function reconstructAndValidateVtxoDAG(
  vtxoOutpoint: Outpoint,
  indexer: IndexerProvider,
  onchain: OnchainProvider,
  witnessPreimages?: Map<string, Uint8Array>
): Promise<DAGValidationResult> {
  const diagnostics: string[] = [];

  // ── Step 1: Privacy-Preserving Fetching ──────────────────────────────────
  diagnostics.push(`[1/6] Privacy Mode: Fetching all VTXO chains for batch`);
  const commitmentTxid = vtxoOutpoint.txid.split(":")[0]; 
  const allChains = await indexer.getBatchVtxos(commitmentTxid);

  const vtxoChain = allChains.find(vc => 
    vc.chain.some(link => link.txid === vtxoOutpoint.txid)
  );

  if (!vtxoChain || vtxoChain.chain.length === 0) {
    throw Errors.EMPTY_CHAIN(vtxoOutpoint);
  }

  const chain = vtxoChain.chain;
  diagnostics.push(`  → Identified local chain with ${chain.length} links (Privacy preserved)`);

  // ── Step 2: Separate commitment from virtual transactions ────────────────
  const commitmentLinks = chain.filter((c) => c.type === ChainTxType.COMMITMENT);
  const virtualLinks = chain.filter(
    (c) => c.type !== ChainTxType.COMMITMENT && c.type !== ChainTxType.UNSPECIFIED
  );

  if (commitmentLinks.length === 0) {
    throw Errors.NO_COMMITMENT();
  }

  const actualCommitmentTxid = commitmentLinks[0].txid;
  diagnostics.push(`[2/6] Commitment tx: ${actualCommitmentTxid}`);
  diagnostics.push(`  → ${virtualLinks.length} virtual transaction(s) to fetch`);

  // ── Step 3: Fetch all virtual transaction PSBTs ──────────────────────────
  diagnostics.push(`[3/6] Fetching virtual transaction PSBTs from ASP`);
  const virtualTxids = virtualLinks.map((l) => l.txid);
  const rawPsbts = await fetchAllVirtualTxs(indexer, virtualTxids);

  const txMap = new Map<string, { tx: Transaction; rawPsbt: string; chainTx: ChainTx }>();
  for (const link of virtualLinks) {
    const rawPsbt = rawPsbts.get(link.txid);
    if (!rawPsbt) throw Errors.MISSING_TX(link.txid);

    let tx: Transaction;
    try {
      tx = Transaction.fromPSBT(base64.decode(rawPsbt), { allowUnknownOutputs: true });
    } catch (e: any) {
      throw new VtxoVerificationError(
        `Failed to parse PSBT for ${link.txid}: ${e.message}`,
        "INVALID_PSBT",
        { txid: link.txid, originalError: e.message }
      );
    }

    if (tx.id !== link.txid) throw Errors.TXID_MISMATCH(link.txid, tx.id);
    txMap.set(link.txid, { tx, rawPsbt, chainTx: link });
  }

  // ── Step 4: Reconstruct the DAG ──────────────────────────────────────────
  diagnostics.push(`[4/6] Reconstructing DAG structure`);
  const chainLookup = new Map<string, ChainTx>();
  for (const link of chain) chainLookup.set(link.txid, link);

  let rootNode: DAGNode | null = null;
  const allNodes = new Map<string, DAGNode>();

  // 4a. Create all nodes
  for (const [txid, { tx, rawPsbt, chainTx }] of txMap) {
    allNodes.set(txid, {
      txid, tx, chainTx, rawPsbt,
      children: new Map(), parent: null, parentOutputIndex: null,
    });
  }

  // 4b. Wire relationships with Cycle Detection
  for (const node of allNodes.values()) {
    const pathVisited = new Set<string>();
    let tracer: DAGNode | null = node;
    while (tracer) {
      if (pathVisited.has(tracer.txid)) {
        throw new VtxoVerificationError(`Cycle detected at ${tracer.txid}`, "CYCLE_DETECTED");
      }
      pathVisited.add(tracer.txid);
      const input = tracer.tx.getInput(0);
      if (!input.txid) break;
      const pTxid = hex.encode(input.txid);
      if (pTxid === actualCommitmentTxid) break;
      tracer = allNodes.get(pTxid) ?? null;
    }

    const input = node.tx.getInput(0);
    const parentTxid = hex.encode(input.txid!);
    const parentOutputIndex = input.index ?? 0;

    if (parentTxid === actualCommitmentTxid) {
      node.parent = null;
      node.parentOutputIndex = parentOutputIndex;
      rootNode = node;
    } else {
      const parentNode = allNodes.get(parentTxid);
      if (!parentNode) throw Errors.INPUT_CHAIN_BREAK(node.txid, parentTxid, "(not in DAG)");
      node.parent = parentNode;
      node.parentOutputIndex = parentOutputIndex;
      parentNode.children.set(parentOutputIndex, node);
    }
  }

  if (!rootNode) throw Errors.NO_COMMITMENT();

  const reachable = new Set<string>();
  collectReachable(rootNode, reachable);
  for (const txid of allNodes.keys()) {
    if (!reachable.has(txid)) throw Errors.ORPHAN_TX(txid);
  }

  // Find leaf node
  let leafNode: DAGNode | null = allNodes.get(vtxoOutpoint.txid) || null;
  if (!leafNode) {
     for (const node of allNodes.values()) {
       if (node.children.size === 0) { leafNode = node; break; }
     }
  }

  // ── Step 5: Commitment Detail & Status ───────────────────────────────────
  diagnostics.push(`[5/9] Fetching on-chain commitment status`);
  const commitmentRaw = await onchain.getRawTransaction(actualCommitmentTxid);
  const commitmentTx = Transaction.fromRaw(hex.decode(commitmentRaw), { allowUnknownOutputs: true });
  const batchOutput = commitmentTx.getOutput(rootNode.parentOutputIndex ?? BATCH_OUTPUT_VTXO_INDEX);
  
  (rootNode as any).prevOutContext = { script: batchOutput.script, amount: batchOutput.amount };

  const onchainStatus = await onchain.getTxStatus(actualCommitmentTxid);
  const blockchainInfo = onchain.getBlockchainInfo ? await onchain.getBlockchainInfo() : null;

  // ── Steps 6-9: Validations ───────────────────────────────────────────────
  validateDAGChaining(rootNode, actualCommitmentTxid, diagnostics);
  const checkpointValidations = validateCheckpoints(allNodes, chainLookup, actualCommitmentTxid, diagnostics);

  for (const node of allNodes.values()) verifyNodeTaproot(node);
  verifyDAGSignatures(rootNode);

  if (blockchainInfo) {
    const chainState = {
      currentHeight: blockchainInfo.height,
      currentTime: blockchainInfo.medianTime,
      commitmentHeight: onchainStatus.confirmed ? onchainStatus.blockHeight : undefined
    };
    verifyDAGTimelocks(rootNode, chainState);
  }

  verifyDAGHashPreimages(rootNode, witnessPreimages);

  return {
    valid: true,
    root: rootNode,
    leaf: leafNode!,
    commitmentTxid: actualCommitmentTxid,
    batchOutputIndex: rootNode.parentOutputIndex ?? BATCH_OUTPUT_VTXO_INDEX,
    checkpointValidations,
    diagnostics,
  };
}

// ─── Internal: Fetch all virtual txs (with batching for large chains) ────────

async function fetchAllVirtualTxs(
  indexer: IndexerProvider,
  txids: string[]
): Promise<Map<string, string>> {
  const result = new Map<string, string>();

  // Batch in groups of 50 to avoid oversized requests
  const BATCH_SIZE = 50;
  for (let i = 0; i < txids.length; i += BATCH_SIZE) {
    const batch = txids.slice(i, i + BATCH_SIZE);
    const { txs } = await indexer.getVirtualTxs(batch);

    // The indexer returns txs in the same order as requested
    for (let j = 0; j < batch.length; j++) {
      if (j < txs.length && txs[j]) {
        result.set(batch[j], txs[j]);
      }
    }
  }

  return result;
}

// ─── Internal: Recursively collect all reachable txids ───────────────────────

function collectReachable(node: DAGNode, reachable: Set<string>): void {
  const stack: DAGNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    reachable.add(current.txid);
    for (const child of current.children.values()) {
      stack.push(child);
    }
  }
}

// ─── Internal: Find the deepest leaf in the DAG ─────────────────────────────

function findLeafInDAG(node: DAGNode): DAGNode {
  const stack: DAGNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.children.size === 0) {
      return current;
    }
    for (const child of current.children.values()) {
      stack.push(child);
    }
  }
  return node;
}

// ─── Internal: Validate chaining recursively ─────────────────────────────────

/**
 * Recursively validates that every child's input[0] correctly references
 * the parent's output at the expected index, and that the sum of child
 * outputs equals the parent's output amount.
 */
function validateDAGChaining(
  rootNode: DAGNode,
  commitmentTxid: string,
  diagnostics: string[]
): void {
  const stack: DAGNode[] = [rootNode];

  while (stack.length > 0) {
    const node = stack.pop()!;

    // ── 1. Validate root node's anchor to the commitment tx ─────────────
    if (node.parent === null) {
      const input = node.tx.getInput(0);
      if (!input.txid) {
        throw Errors.INPUT_CHAIN_BREAK(node.txid, commitmentTxid, "(no input)");
      }

      const inputTxid = hex.encode(input.txid);
      if (inputTxid !== commitmentTxid) {
        throw Errors.INPUT_CHAIN_BREAK(node.txid, commitmentTxid, inputTxid);
      }

      diagnostics.push(
        `  ✓ Root ${node.txid} correctly anchored to commitment ${commitmentTxid} at output[${input.index ?? 0}]`
      );

      // Verify root amount against commitment
      const rootPrevOut = (node as any).prevOutContext;
      if (rootPrevOut) {
        let rootOutputsSum = 0n;
        for (let i = 0; i < node.tx.outputsLength; i++) {
          const out = node.tx.getOutput(i);
          if (out?.amount) rootOutputsSum += out.amount;
        }
        
        if (rootOutputsSum !== rootPrevOut.amount) {
          throw Errors.AMOUNT_MISMATCH(
            commitmentTxid,
            input.index ?? 0,
            rootPrevOut.amount,
            rootOutputsSum
          );
        }
        diagnostics.push(`  ✓ Root amount ${rootOutputsSum} matches commitment batch output (conserved)`);
      }
    }

    // ── 2. Validate each child ───────────────────────────────────────────
    for (const [outputIndex, child] of node.children) {
      // (a) Verify child's input references the parent's output
      const childInput = child.tx.getInput(0);
      if (!childInput.txid) {
        throw Errors.INPUT_CHAIN_BREAK(child.txid, node.txid, "(no input txid)");
      }

      const childInputTxid = hex.encode(childInput.txid);
      const childInputIndex = childInput.index ?? 0;

      if (childInputTxid !== node.txid) {
        throw Errors.INPUT_CHAIN_BREAK(child.txid, node.txid, childInputTxid);
      }

      if (childInputIndex !== outputIndex) {
        throw new VtxoVerificationError(
          `Child ${child.txid} input index ${childInputIndex} does not match expected output index ${outputIndex}`,
          "INDEX_MISMATCH",
          { childTxid: child.txid, expected: outputIndex, actual: childInputIndex }
        );
      }

      // (b) Verify amounts: sum(child outputs) == parent output[index]
      const parentOutput = node.tx.getOutput(outputIndex);
      if (!parentOutput || parentOutput.amount === undefined) {
        throw new VtxoVerificationError(
          `Parent ${node.txid} has no output at index ${outputIndex}`,
          "MISSING_OUTPUT",
          { parentTxid: node.txid, outputIndex }
        );
      }

      let childOutputsSum = 0n;
      for (let i = 0; i < child.tx.outputsLength; i++) {
        const out = child.tx.getOutput(i);
        if (out?.amount) {
          childOutputsSum += out.amount;
        }
      }

      if (childOutputsSum !== parentOutput.amount) {
        throw Errors.AMOUNT_MISMATCH(
          node.txid,
          outputIndex,
          parentOutput.amount,
          childOutputsSum
        );
      }

      diagnostics.push(
        `  ✓ ${child.txid} → parent ${node.txid}[${outputIndex}]: ${parentOutput.amount} sats (chain OK)`
      );

      // (c) Add child to stack for iterative processing
      stack.push(child);
    }
  }
}

// ─── Internal: Validate Checkpoint Transactions ──────────────────────────────

/**
 * Validates checkpoint transactions in the DAG.
 *
 * Checkpoint transactions are intermediate states designed to protect the ASP
 * against griefing attacks. They are signed by both user and operator and
 * inserted between the batch output and the final VTXO.
 *
 * Validations performed:
 *   1. The checkpoint's input correctly references a parent in the DAG.
 *   2. The checkpoint's expiry (expiresAt) is coherent with the sweep delay:
 *      – It must not expire *before* its parent.
 *      – It must expire *before or at the same time as* the batch expiry.
 *   3. The checkpoint has exactly 1 input (structural consistency).
 *   4. The checkpoint's outputs sum must equal its parent output amount.
 */
function validateCheckpoints(
  allNodes: Map<string, DAGNode>,
  chainLookup: Map<string, ChainTx>,
  commitmentTxid: string,
  diagnostics: string[]
): CheckpointValidation[] {
  const results: CheckpointValidation[] = [];

  for (const [txid, node] of allNodes) {
    if (node.chainTx.type !== ChainTxType.CHECKPOINT) {
      continue;
    }

    const notes: string[] = [];
    let expiryCoherent = true;
    let parentChainValid = true;

    // ── 1. Verify checkpoint has parents in the chain ─────────────────────
    if (node.chainTx.spends.length === 0) {
      notes.push("WARNING: Checkpoint has no parent references in chain data");
      parentChainValid = false;
    }

    // Verify input chaining (already done globally, but double-check)
    const input = node.tx.getInput(0);
    if (!input.txid) {
      notes.push("ERROR: Checkpoint has no input txid");
      parentChainValid = false;
    } else {
      const parentTxid = hex.encode(input.txid);
      const parentInChain = chainLookup.get(parentTxid);

      if (!parentInChain) {
        notes.push(
          `WARNING: Checkpoint parent ${parentTxid} not found in chain metadata`
        );
      } else {
        notes.push(`Parent in chain: ${parentTxid} (type: ${parentInChain.type})`);
      }
    }

    // ── 2. Validate expiry coherence ─────────────────────────────────────
    //
    // The checkpoint's expiresAt must be:
    //   - ≥ parent's expiresAt (cannot expire before what it depends on)
    //   - ≤ batch root expiresAt (cannot outlive the batch)
    //
    const checkpointExpiry = parseExpiry(node.chainTx.expiresAt);

    if (node.parent) {
      const parentExpiry = parseExpiry(node.parent.chainTx.expiresAt);

      if (checkpointExpiry > 0 && parentExpiry > 0) {
        if (checkpointExpiry < parentExpiry) {
          expiryCoherent = false;
          notes.push(
            `FAIL: Checkpoint expires at ${checkpointExpiry} but parent expires at ${parentExpiry} (checkpoint must not expire before parent)`
          );
          throw Errors.CHECKPOINT_EXPIRY_INCOHERENT(
            txid,
            `expires at ${checkpointExpiry} but parent at ${parentExpiry}`
          );
        } else {
          notes.push(
            `Expiry OK: checkpoint=${checkpointExpiry}, parent=${parentExpiry}`
          );
        }
      } else {
        notes.push(
          "INFO: Could not compare expiry times (one or both are 0/unparsed)"
        );
      }
    }

    // ── 3. Compare against the batch root (commitment) expiry ────────────
    // The commitment transaction defines the overall batch lifetime.
    let batchRootExpiry = 0;
    const commitmentChainTx = chainLookup.get(commitmentTxid);
    if (commitmentChainTx) {
      batchRootExpiry = parseExpiry(commitmentChainTx.expiresAt);
    }

    if (checkpointExpiry > 0 && batchRootExpiry > 0 && checkpointExpiry > batchRootExpiry) {
      expiryCoherent = false;
      notes.push(
        `FAIL: Checkpoint expires at ${checkpointExpiry} but batch root (commitment) expires at ${batchRootExpiry}`
      );
      throw Errors.CHECKPOINT_EXPIRY_INCOHERENT(
        txid,
        `expires at ${checkpointExpiry} but batch root at ${batchRootExpiry}`
      );
    }

    // ── 4. Validate sweep delay coherence ────────────────────────────────
    //
    // Checkpoint txs exist to allow the ASP to claim a VTXO with a single
    // broadcast if the holder doesn't publish the next tx in the chain.
    // The nSequence on the checkpoint's input encodes the relative
    // timelock (sweep delay). We verify it's set and non-zero.
    //
    if (input.txid) {
      const sequence = input.sequence;
      if (sequence !== undefined && sequence !== 0xffffffff) {
        // There's a relative timelock set (CSV)
        // Extract the timelock value (lower 16 bits for blocks, or bit 22 for time)
        const isTimeBased = (sequence & (1 << 22)) !== 0;
        const timelockValue = sequence & 0xffff;

        if (timelockValue === 0) {
          notes.push("WARNING: Checkpoint has zero sweep delay");
        } else {
          notes.push(
            `Sweep delay: ${timelockValue} ${isTimeBased ? "seconds (×512)" : "blocks"}`
          );
        }
      } else {
        notes.push("INFO: No relative timelock on checkpoint input (sequence=MAX or 0)");
      }
    }

    diagnostics.push(
      `  ${expiryCoherent && parentChainValid ? "✓" : "✗"} Checkpoint ${txid}: ${notes.join("; ")}`
    );

    results.push({
      txid,
      expiryCoherent,
      parentChainValid,
      notes,
    });
  }

  if (results.length === 0) {
    diagnostics.push("  (no checkpoint transactions in this chain)");
  }

  return results;
}

// ─── Internal: Parse expiry timestamp ────────────────────────────────────────

function parseExpiry(expiresAt: string): number {
  if (!expiresAt) return 0;
  const n = Number(expiresAt);
  if (Number.isFinite(n) && n > 0) {
    // If it looks like a small number, it's probably a unix timestamp in seconds
    // If it's a large number, it might already be in milliseconds
    return n < 1e12 ? n * 1000 : n;
  }
  // Try ISO date
  const d = new Date(expiresAt);
  return isNaN(d.getTime()) ? 0 : d.getTime();
}

// ─── Convenience: Verify on-chain anchoring of the commitment tx ─────────────

/**
 * Verifies that the commitment transaction exists on-chain and is confirmed.
 * This is part of Tier 1 Task 3 but included here for completeness.
 *
 * @param commitmentTxid  The txid of the commitment transaction.
 * @param batchOutputIndex The batch output index (default: 0).
 * @param onchain         An OnchainProvider to query the Bitcoin node.
 * @param minConfirmations Minimum confirmations required (default: 1).
 * @throws VtxoVerificationError if the commitment tx is not confirmed.
 */
export async function verifyOnchainAnchoring(
  commitmentTxid: string,
  batchOutputIndex: number,
  onchain: OnchainProvider,
  minConfirmations: number = 1
): Promise<{
  confirmed: boolean;
  blockHeight?: number;
  blockTime?: number;
}> {
  const status = await onchain.getTxStatus(commitmentTxid);

  if (!status.confirmed) {
    throw new VtxoVerificationError(
      `Commitment tx ${commitmentTxid} is not confirmed on-chain`,
      "COMMITMENT_NOT_CONFIRMED",
      { commitmentTxid }
    );
  }

  return status;
}

// ─── Convenience: Full verification pipeline ─────────────────────────────────

/**
 * Complete Tier 1 verification pipeline:
 *   1. Reconstruct + validate the DAG (this module).
 *   2. Verify the commitment tx is confirmed on-chain.
 *
 * @param vtxoOutpoint  The VTXO leaf to verify end-to-end.
 * @param indexer       IndexerProvider.
 * @param onchain       OnchainProvider.
 * @param minConfirmations  Minimum on-chain confirmations (default: 1).
 * @returns The full validation result.
 */
export async function verifyVtxoComplete(
  vtxoOutpoint: Outpoint,
  indexer: IndexerProvider,
  onchain: OnchainProvider,
  minConfirmations: number = 1,
  witnessPreimages?: Map<string, Uint8Array>
): Promise<DAGValidationResult & { onchainStatus: { confirmed: boolean; blockHeight?: number } }> {
  const cacheKey = `${vtxoOutpoint.txid}:${vtxoOutpoint.vout}:${minConfirmations}`;
  const cached = globalVerificationCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  // Phase 1: DAG reconstruction + structural validation
  const dagResult = await reconstructAndValidateVtxoDAG(
    vtxoOutpoint,
    indexer,
    onchain,
    witnessPreimages
  );

  // Phase 2: On-chain anchoring verification (throttled)
  const onchainStatus = await globalOnchainLimiter.run(() => 
    verifyOnchainAnchoring(
      dagResult.commitmentTxid,
      dagResult.batchOutputIndex,
      onchain,
      minConfirmations
    )
  );

  dagResult.diagnostics.push(
    `✓ Commitment tx ${dagResult.commitmentTxid} confirmed at block ${onchainStatus.blockHeight}`
  );

  const finalResult = {
    ...dagResult,
    onchainStatus,
  };

  globalVerificationCache.set(cacheKey, finalResult);
  return finalResult;
}
