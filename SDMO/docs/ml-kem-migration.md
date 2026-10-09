# ML-KEM Integration Proposal

## Current Baseline

Gateway and cloud share a long-lived `SHARED_KEY`; the gateway sends it in `X-Legacy-Shared-Key` over plain HTTP on the Compose network. This static, out-of-band key has no negotiation, rotation, identity lifecycle, or post-quantum protection. The default is for local simulation only.

## Proposed Direction

Replace static key provisioning with an authenticated, versioned session-establishment protocol using standardized ML-KEM-768 from a maintained cryptographic library. ML-KEM establishes shared key material but does not authenticate the gateway. Bind the exchange to authenticated identities and protocol context, derive traffic keys with a standard KDF, and protect records with standard AEAD. Do not implement these primitives or a custom wire protocol locally.

## Stages

1. Define identities, trust anchors, rotation, replay handling, downgrade behavior, and the constrained-device message budget.
2. Select a maintained implementation for gateway and cloud platforms; validate it against applicable NIST vectors and the library's security guidance.
3. Add key confirmation and transcript binding; make any classical/ML-KEM transition policy explicit and forbid silent fallback.
4. Test interoperability, malformed messages, replay, downgrade, rotation, and recovery before deployment.
5. Remove static-key mode after migration and document key custody and incident rotation.

Proposal only: this starter implements no post-quantum cryptography.
