import { describe, it, expect, beforeEach } from "vitest";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
import { p2tr } from "@scure/btc-signer/payment.js";
import {
  TEST_PRIVKEYS,
  createVirtualTx,
  signVirtualTx,
  fakeCommitmentTxid,
  makeP2TRScript,
  MockIndexerProvider,
  MockOnchainProvider
} from "./vtxoDAGVerification.test.js";
import { 
  ChainTxType, 
  reconstructAndValidateVtxoDAG,
  verifyVtxoComplete 
} from "../vtxoDAGVerification.js";

describe("Black Box Security Audit: Malicious ASP Resilience", () => {
  let indexer: MockIndexerProvider;
  let onchain: MockOnchainProvider;

  beforeEach(() => {
    indexer = new MockIndexerProvider();
    onchain = new MockOnchainProvider();
  });

  // ─── Scenario 1: The Mirage Attack ───────────────────────────────────────
  it("MIRAGE: should reject a VTXO when the commitment transaction is missing on-chain", async () => {
    const commitmentTxid = fakeCommitmentTxid(404); // Not in onchain.txs
    
    // We create a structural chain metadata, but the root anchor is floating in a mirage
    const vtxoTx = createVirtualTx(commitmentTxid, 0, [{ amount: 100000n }]);
    
    indexer.chain = [
      { txid: vtxoTx.txid, expiresAt: "2000000000", type: ChainTxType.ARK, spends: [commitmentTxid] },
      { txid: commitmentTxid, expiresAt: "2000000000", type: ChainTxType.COMMITMENT, spends: [] }
    ];
    indexer.virtualTxs.set(vtxoTx.txid, base64.encode(vtxoTx.tx.toPSBT()));

    // The SDK should fail when attempting to fetch the commitment raw hex
    await expect(reconstructAndValidateVtxoDAG({ txid: vtxoTx.txid, vout: 0 }, indexer, onchain))
      .rejects.toThrow(); // Should fail at Step 5a: getRawTransaction
  });

  it("MIRAGE: should reject a VTXO when the commitment is found but NOT confirmed", async () => {
    const commitmentTxid = fakeCommitmentTxid(202);
    const commitmentRaw = createVirtualTx(fakeCommitmentTxid(203), 0, [{ amount: 100000n }]);
    
    // Found in node, but NOT confirmed
    onchain.txs.set(commitmentTxid, hex.encode(commitmentRaw.tx.toBytes()));
    // onchain.confirmedTxids.add(commitmentTxid); // OMITTED intentionally

    const vtxoTx = createVirtualTx(commitmentTxid, 0, [{ amount: 100000n }], {
        parentScript: makeP2TRScript(1),
        tapInternalKey: schnorr.getPublicKey(TEST_PRIVKEYS[1])
    });
    signVirtualTx(vtxoTx.tx, 0, TEST_PRIVKEYS[1], [{ script: makeP2TRScript(1), amount: 100000n }]);
    
    indexer.chain = [
      { txid: vtxoTx.txid, expiresAt: "2000000000", type: ChainTxType.ARK, spends: [commitmentTxid] },
      { txid: commitmentTxid, expiresAt: "2000000000", type: ChainTxType.COMMITMENT, spends: [] }
    ];
    indexer.virtualTxs.set(vtxoTx.txid, base64.encode(vtxoTx.tx.toPSBT()));

    // Use verifyVtxoComplete to trigger the on-chain status check (verifyOnchainAnchoring)
    await expect(verifyVtxoComplete({ txid: vtxoTx.txid, vout: 0 }, indexer, onchain, 1))
      .rejects.toThrow(/COMMITMENT_NOT_CONFIRMED/);
  });

  // ─── Scenario 2: Data Poisoning ──────────────────────────────────────────
  it("POISON: should reject corrupted PSBT data and prevent SDK crash", async () => {
    const commitmentTxid = fakeCommitmentTxid(500);
    const vtxoTxid = "vtxo_poison_01";
    
    indexer.chain = [
      { txid: vtxoTxid, expiresAt: "2000000000", type: ChainTxType.ARK, spends: [commitmentTxid] },
      { txid: commitmentTxid, expiresAt: "2000000000", type: ChainTxType.COMMITMENT, spends: [] }
    ];

    // Inject "poison" PSBT - valid base64 but invalid internal structure (just dummy bytes)
    const poisonData = base64.encode(new Uint8Array([0x42, 0x42, 0x42, 0x42, 0x00, 0xff]));
    indexer.virtualTxs.set(vtxoTxid, poisonData);

    // reconstructAndValidateVtxoDAG should catch the decoding error during Transaction.fromPSBT
    await expect(reconstructAndValidateVtxoDAG({ txid: vtxoTxid, vout: 0 }, indexer, onchain))
      .rejects.toThrow(); 
  });

  // ─── Scenario 3: Checkpoint Forgery ──────────────────────────────────────
  it("FORGERY: should reject Checkpoints with incoherent expiry (expires before parent)", async () => {
    const commitmentTxid = fakeCommitmentTxid(600);
    const commitmentRaw = createVirtualTx(fakeCommitmentTxid(601), 0, [
      { amount: 100000n, script: makeP2TRScript(1) }
    ]);
    onchain.txs.set(commitmentTxid, hex.encode(commitmentRaw.tx.toBytes()));
    onchain.confirmedTxids.add(commitmentTxid);

    // Parent (Tree node)
    const treeTx = createVirtualTx(commitmentTxid, 0, [{ amount: 100000n }], {
      parentScript: makeP2TRScript(1),
      tapInternalKey: schnorr.getPublicKey(TEST_PRIVKEYS[1])
    });
    
    // Checkpoint Node - FORGED: expires at 1000 while parent expires at 2000
    const checkpointTx = createVirtualTx(treeTx.txid, 0, [{ amount: 100000n }], {
      parentScript: makeP2TRScript(2),
      tapInternalKey: schnorr.getPublicKey(TEST_PRIVKEYS[2])
    });

    indexer.chain = [
      { txid: checkpointTx.txid, expiresAt: "1000", type: ChainTxType.CHECKPOINT, spends: [treeTx.txid] },
      { txid: treeTx.txid, expiresAt: "2000", type: ChainTxType.TREE, spends: [commitmentTxid] },
      { txid: commitmentTxid, expiresAt: "3000", type: ChainTxType.COMMITMENT, spends: [] }
    ];
    
    indexer.virtualTxs.set(treeTx.txid, base64.encode(treeTx.tx.toPSBT()));
    indexer.virtualTxs.set(checkpointTx.txid, base64.encode(checkpointTx.tx.toPSBT()));

    await expect(reconstructAndValidateVtxoDAG({ txid: checkpointTx.txid, vout: 0 }, indexer, onchain))
      .rejects.toThrow(/CHECKPOINT_EXPIRY_INCOHERENT/);
  });

  it("FORGERY: should reject trivial OP_TRUE script injections for policy bypass", async () => {
    const commitmentTxid = fakeCommitmentTxid(700);
    const commitmentRaw = createVirtualTx(fakeCommitmentTxid(701), 0, [
      { amount: 100000n, script: makeP2TRScript(1) }
    ]);
    onchain.txs.set(commitmentTxid, hex.encode(commitmentRaw.tx.toBytes()));
    onchain.confirmedTxids.add(commitmentTxid);

    // MALICIOUS SCRIPT: just OP_TRUE (0x51).
    const trivialScript = new Uint8Array([0x51]); 
    const internalKey = schnorr.getPublicKey(TEST_PRIVKEYS[1]);
    
    // Use p2tr helper to get a perfectly formatted but conceptually malicious leaf
    const tr = p2tr(internalKey, { script: trivialScript }, undefined, true);

    const vtxoTx = createVirtualTx(commitmentTxid, 0, [{ amount: 100000n }], {
        parentScript: tr.script,
        tapInternalKey: internalKey,
        tapLeafScript: tr.tapLeafScript,
        tapMerkleRoot: tr.tapMerkleRoot
    });

    indexer.chain = [
      { txid: vtxoTx.txid, expiresAt: "2000", type: ChainTxType.ARK, spends: [commitmentTxid] },
      { txid: commitmentTxid, expiresAt: "3000", type: ChainTxType.COMMITMENT, spends: [] }
    ];
    indexer.virtualTxs.set(vtxoTx.txid, base64.encode(vtxoTx.tx.toPSBT()));

    // Should be blocked by verifyArkExitPolicy (Structural Parsing Hardening)
    await expect(reconstructAndValidateVtxoDAG({ txid: vtxoTx.txid, vout: 0 }, indexer, onchain))
      .rejects.toThrow(/SECURITY_VIOLATION/);
  });
});
