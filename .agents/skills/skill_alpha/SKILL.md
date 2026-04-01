---
name: VTXO DAG Verification
description: Client-side VTXO chain verification for the Arkade SDK — reconstructs and validates the full DAG from leaf to batch output root.
---

# VTXO DAG Verification Skill

## Role
Senior TypeScript developer specialized in the Bitcoin protocol, Ark, and elliptic-curve cryptography.

## Task Context
Implementing client-side VTXO verification for the Arkade SDK. The goal is to guarantee self-custody without blindly trusting the Ark Service Provider (ASP).

## Strict Constraints
- **Zero Trust**: Every datum from the ASP is potentially malicious.
- **Tier 1 Only**: Structural DAG validation, Schnorr/MuSig2 signature verification, and on-chain anchoring. No Taproot script validation.
- **Dependencies**: Only standard Bitcoin cryptographic libraries already in the TypeScript ecosystem (`@scure/btc-signer`, `@scure/base`, `@noble/curves`).
- **Environment**: All Bitcoin node queries target a local regtest node.