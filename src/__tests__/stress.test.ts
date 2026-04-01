import { describe, it, expect, beforeEach } from "vitest";
import { hex, base64 } from "@scure/base";
import { schnorr } from "@noble/curves/secp256k1.js";
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

describe("Stress Test: Extreme VTXO DAGs", () => {
  let indexer: MockIndexerProvider;
  let onchain: MockOnchainProvider;

  beforeEach(() => {
    indexer = new MockIndexerProvider();
    onchain = new MockOnchainProvider();
  });

  /**
   * Generates a deep linear DAG of virtual transactions.
   * Root -> T1 -> T2 -> ... -> Tn (Leaf)
   */
  async function generateDeepLinearChain(depth: number) {
    const commitmentTxid = fakeCommitmentTxid(999);
    const rootScript = makeP2TRScript(0);
    const commitmentRaw = createVirtualTx(fakeCommitmentTxid(1000), 0, [{ amount: 1000000n, script: rootScript }]);
    onchain.txs.set(commitmentTxid, hex.encode(commitmentRaw.tx.toBytes()));
    onchain.confirmedTxids.add(commitmentTxid);

    indexer.chain = [
      { txid: commitmentTxid, expiresAt: "3000", type: ChainTxType.COMMITMENT, spends: [] }
    ];

    let lastTxid = commitmentTxid;
    let lastScript = rootScript;
    let lastKey = TEST_PRIVKEYS[0];

    for (let i = 1; i <= depth; i++) {
        const currentKey = TEST_PRIVKEYS[i % TEST_PRIVKEYS.length];
        const currentScript = makeP2TRScript(i % TEST_PRIVKEYS.length);
        const vtx = createVirtualTx(lastTxid, 0, [{ amount: 1000000n, script: currentScript }], {
            parentScript: lastScript,
            tapInternalKey: schnorr.getPublicKey(lastKey)
        });
        
        signVirtualTx(vtx.tx, 0, lastKey, [{ script: lastScript, amount: 1000000n }]);
        
        indexer.virtualTxs.set(vtx.txid, base64.encode(vtx.tx.toPSBT()));
        indexer.chain.unshift({ 
            txid: vtx.txid, 
            expiresAt: (3000 + i).toString(), 
            type: i === depth ? ChainTxType.ARK : ChainTxType.TREE, 
            spends: [lastTxid] 
        });

        lastTxid = vtx.txid;
        lastScript = currentScript;
        lastKey = currentKey;
    }

    return lastTxid;
  }

  it("STRESS: should attempt to verify a depth=10000 chain (Expect Stack Overflow)", async () => {
    console.time("DAG-Generation-10000");
    const leafTxid = await generateDeepLinearChain(10000);
    console.timeEnd("DAG-Generation-10000");

    console.time("Verification-10000");
    try {
        const result = await verifyVtxoComplete({ txid: leafTxid, vout: 0 }, indexer, onchain);
        expect(result.valid).toBe(true);
        console.log("✓ Verification of 10000-deep chain succeeded (High stack limit environment?)");
    } catch (e: any) {
        console.error("✗ Stress Test Failure:", e.message);
        if (e instanceof RangeError || e.message.includes("stack size")) {
            console.log("!!! SE CONFIRMA PUNTO DE RUPTURA: Stack Overflow detectado en profundidad 10000.");
        }
        throw e;
    } finally {
        console.timeEnd("Verification-10000");
    }
  }, 120000);

  it("STRESS: should test I/O and On-chain RPC concurrency bottleneck", async () => {
      const leafTxid = await generateDeepLinearChain(10); // Small but many
      const CONCURRENCY = 100;
      
      console.time(`Concurrency-${CONCURRENCY}`);
      const promises = Array.from({ length: CONCURRENCY }).map(() => 
         verifyVtxoComplete({ txid: leafTxid, vout: 0 }, indexer, onchain)
      );

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === "fulfilled").length;
      console.timeEnd(`Concurrency-${CONCURRENCY}`);
      
      console.log(`✓ Concurrency results: ${successful}/${CONCURRENCY} successful`);
      expect(successful).toBe(CONCURRENCY);
  });
});
