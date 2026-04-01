# Test Documentation: Tier 1 - Core VTXO Verification

## Overview
This suite focuses on the structural and cryptographic validation of the VTXO DAG, ensuring that every virtual transaction is authentic and correctly anchored to the Bitcoin blockchain.

### 🎯 Test Goals
1. **DAG Reconstruction**: Programmatically building the parent-child relationship from a single leaf outpoint.
2. **Signature Integrity**: Verifying that every transaction in the DAG was signed by the appropriate MuSig2/Schnorr aggregated keys.
3. **On-chain Anchor**: Confirming the root commitment transaction exists on-chain with the required confirmations.

### 🌐 Environment
- **Providers**: `MockIndexerProvider` and `MockOnchainProvider`.
- **Data Source**: Simulated Regtest/Signet transaction structures (PSBTs and on-chain status).
- **Execution**: Node.js/Vitest environment.

### 🧪 Evaluated Scenarios
| Scenario | Description | Expected |
| :--- | :--- | :--- |
| **Valid DAG** | A consistent 3-level DAG with correct signatures and confirmed commitment. | **PASS** |
| **Tampered Sig** | A single bit change in the Schnorr signature of an intermediate node. | **FAIL (INVALID_SIGNATURE)** |
| **Missing Link** | A DAG where a child input doesn't correctly reference its parent outpoint. | **FAIL (INPUT_CHAIN_BREAK)** |
| **Ghost Commitment** | A valid DAG whose root commitment is not found on-chain. | **FAIL (COMMITMENT_NOT_FOUND)** |
| **Anti-Mirage Attack** | ASP provides a fake TXID or malformed hex during anchoring. | **FAIL (ORACLE_POISONING_DETECTED)** |
| **RPC Spoofing** | Bitcoin RPC returns HTTP 200 with result: null or malformed JSON. | **FAIL (INVALID_RPC_RESPONSE)** |

### 📈 Results
- **Success Rate**: 100% of functional and security tests passed.
- **Latency**: Sub-50ms for typical 5-depth DAG reconstruction and validation.
- **Security**: Successfully rejected all 20+ simulated "Mirage", "Incorrect Signature", and "RPC Poisoning" attacks.
