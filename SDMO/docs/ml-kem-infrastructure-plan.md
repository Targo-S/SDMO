# SDMO ML-KEM Migration and Infrastructure Change Plan

Scope: the simulation only. This plan makes no code changes. It builds on [ml-kem-migration.md](ml-kem-migration.md).

## 0. Current implementation

**Data flow.** [legacy_device.py](../sdmo/legacy_device.py) serves `GET /v1/reading` with `device_id`, `sequence`, `temperature_c` and `observed_at`. It is unauthenticated plain HTTP and can only be reached inside Compose. [gateway.py](../sdmo/gateway.py) polls it every 5 seconds and POSTs each reading to the cloud's `/v1/readings` over plain HTTP. [cloud.py](../sdmo/cloud.py) stores the readings in memory and counts rejected requests.

**Authentication.** The gateway sends `X-Legacy-Shared-Key` with every request. The cloud checks it with `hmac.compare_digest`. The key is static, set through the environment, and defaults to `demo-only-change-me`.

**Constraints that shape the plan:**

- `poll_once()` is stateless and takes a `shared_key` argument. A PQ session needs state in the gateway (the session and its counter) and in the cloud (the session table), so the function and `CloudState` must change.
- `read_json()` in [common.py](../sdmo/common.py) caps request bodies at 64 KB, which is ample for handshake messages of about 1.2 to 2 KB.
- The `/metrics` code is duplicated in the gateway and cloud and is hand-formatted. It needs labels and histograms, so it should be shared.
- The project has no dependencies, and the [Dockerfile](../Dockerfile) is `python:3.14-slim` with no compiler. Adding a native crypto library is the biggest infrastructure change.
- `/v1/readings` does not deduplicate readings.
- The existing two tests in [test_pipeline.py](../tests/test_pipeline.py) exercise the shared-key path and must keep passing in "legacy mode" throughout.

**Scope caveat.** The proposal doc says not to write a custom wire protocol. For the simulation, this plan proposes a small application-layer handshake built only from standard primitives. That is the only way to exercise ML-KEM end-to-end and test it. The production target is TLS 1.3 with a hybrid key exchange (see section 7). The simulation protocol is a stand-in for that, not a recommendation to ship it.

## 1. ML-KEM integration and library choice

### Architecture decision

- The gateway is the post-quantum termination point and translates between the two link types.
- Gateway to cloud uses hybrid key establishment: ephemeral X25519 plus ML-KEM-768. The two secrets are combined with HKDF-SHA256 and bound to the handshake transcript. Records are protected with AES-256-GCM or ChaCha20-Poly1305.
- The device to gateway link stays classical. It uses a per-device symmetric key (section 2).

**Why hybrid.** ML-KEM is new, and its implementations have had side-channel bugs. A hybrid is only broken if both X25519 and ML-KEM are broken. This is the approach in current TLS and SSH deployments.

**Why ephemeral keys per session.** This gives forward secrecy, which a static shared key never had.

### Handshake (new endpoint `POST /v2/handshake`)

1. The gateway sends `{v, gateway_id, suites[], mlkem_ek, x25519_pub, nonce_g}`. `mlkem_ek` is an ephemeral ML-KEM encapsulation key.
2. The cloud validates the message (lengths, allowed suite, known gateway) and runs ML-KEM `Encaps(ek)`, which gives `ct` and `ss_pq`. It generates its own X25519 key and derives `ss_ec`. It then computes `K = HKDF-SHA256(ikm = ss_pq || ss_ec, salt = nonce_g || nonce_c, info = "sdmo/v2" || H(transcript))`. It returns `{session_id, ct, x25519_pub, nonce_c, signature, confirm}`.
3. The gateway verifies the cloud's signature against a pinned identity key, runs `Decaps(ct)`, derives the same `K` and checks `confirm`. Its first record carries its own confirmation MAC.
4. Records go to `POST /v2/readings` as `{session_id, counter, ciphertext}`. The AAD is session_id plus counter plus path. The nonce is a direction prefix plus the counter. The counter must strictly increase, which gives replay protection.

### Authentication choices

- **Cloud authentication.** The cloud signs the transcript with Ed25519. The gateway pins its public key.
- **Gateway authentication.** The gateway proves itself with an HMAC over the transcript, keyed with a per-gateway enrollment secret. That secret replaces the global `SHARED_KEY`.
- **Why this split.** Symmetric HMAC is quantum-resistant. Ed25519 would only be forgeable by a future quantum attacker, and only for an active attack during a handshake. It does not allow the retroactive decryption of recorded traffic that ML-KEM exists to stop. Swapping Ed25519 for ML-DSA-65 is a later optional stage using the same library.

### Library comparison and recommendation

Recommended: **liboqs-python** (Open Quantum Safe) for the KEM, plus **pyca/cryptography** for X25519, HKDF, AEAD and Ed25519.

| Option | Verdict | Why |
|---|---|---|
| liboqs-python | Chosen | One API for ML-KEM-512, 768 and 1024. It wraps a maintained C library under the Linux Foundation's PQCA, with FIPS 203 final names and constant-time C code. The same library covers ML-DSA later. |
| pqcrypto (PQClean bindings) | Rejected | Easy wheels and a simple API, but it depends on PQClean, which has had reduced upstream maintenance. It offers fewer algorithms and gives less confidence about update cadence. |
| kyber-py (pure Python) | Test oracle only | Readable and easy to install, but not constant-time and slow. It is useful for differential testing, not for runtime use. |
| pyca/cryptography alone | Not for the KEM | It is the right choice for classical primitives and HKDF. It is unconfirmed whether it exposes ML-KEM in a stable API, so re-check this at implementation time. If it does, it becomes the preferred backend. |
| Python stdlib | Not possible | It has no ML-KEM. |

**Caveats to handle:**

- liboqs-python needs the native liboqs library, and the Python and C versions must match. Pin both exactly.
- Python 3.14 compatibility must be verified.
- The OQS project says it is not yet recommended for production on its own, which is another reason to run it in hybrid with X25519.
- Do not let liboqs-python auto-build at first import in the container, because that is a runtime supply-chain risk. Build liboqs at image build time.

### Infrastructure changes for this step

1. Add a dependency manifest: a lock file with hashes for liboqs-python and cryptography. Update `pyproject.toml` and add `requirements.lock`.
2. Make the Dockerfile multi-stage. The builder stage compiles a pinned, checksum-verified liboqs with cmake. The runtime stage copies the shared library and a venv. It keeps the non-root user.
3. Add a thin `sdmo/crypto.py` abstraction with `kem_keygen`, `encaps` and `decaps`, with the backend selected by config. This is justified because it isolates the library and makes the later swaps in section 7 cheap. It must not expose parameter sets outside an allowlist.
4. Replace `SHARED_KEY` in `compose.yaml` with per-gateway enrollment secrets and the cloud identity key, supplied as Docker secrets or files and not as environment variables.
5. Make `CloudState` hold the identity key, a gateway registry, a session table with a size cap, and an expiry sweep. Make the gateway hold a `Session` object with a reconnect loop.
6. At startup run a self-test (a known-answer decapsulation), fail closed if it does not pass, and report the result in metrics.

## 2. Legacy (Arduino-class) compatibility and the hybrid migration and fallback strategy

### What can and cannot be preserved

An Arduino Uno-class board has about 2 KB of RAM. ML-KEM-768 needs an encapsulation key of 1184 B, a ciphertext of 1088 B and several KB of working memory. That is not feasible on AVR. Cortex-M4 class parts can run ML-KEM, but not the typical legacy 8-bit fleet. So the device does not speak ML-KEM, and the gateway does it on its behalf.

### Device-side design (classical and quantum-safe)

- Derive a per-device key `K_dev = HKDF(gateway_master, device_id)`. Use it for an authenticated frame: a MAC or AEAD (ChaCha20-Poly1305) over the reading plus a monotonic counter.
- A 128-bit or 256-bit symmetric key keeps its security margin against quantum attacks (Grover only halves it). It needs no ML-KEM.
- Real Arduino libraries exist for this (the Crypto library from rweather has ChaChaPoly, SHA256 and Ed25519).
- Real Arduinos usually lack a wall clock. The gateway should therefore be allowed to set `observed_at`, and it should be marked as gateway-assigned.
- In the simulation, add an optional `DEVICE_KEY` to `legacy_device.py` that makes the reading carry a MAC and counter. Leave it off by default so the original behaviour remains.
- The device keeps polling over HTTP in the sim, but the gateway must verify the MAC when a key is configured.

**Trade-off.** The gateway becomes a trusted point, and end-to-end device-to-cloud confidentiality is lost. This is acceptable in the sim, and the trade-off should be documented. Where it is not acceptable, layer a payload key between device and cloud.

### Migration and fallback strategy

Modes: `legacy` (current), `hybrid` (X25519 + ML-KEM-768) and `pq-only` (reserved, not the default).

- **Phase 0, instrument.** Add monitoring (section 4) before any protocol change so every later phase can be measured. Exit when the legacy request count is visible.
- **Phase 1, cloud dual-stack.** The cloud serves `/v1` (static key) and `/v2` (hybrid), with policy `ACCEPT_MODES=legacy,hybrid`. Legacy use is counted and logged as deprecated. Exit when the existing tests pass in both modes.
- **Phase 2, gateway prefers hybrid.** `PREFERRED_MODE=hybrid`. Fallback to legacy is allowed only when the cloud reports that it lacks v2 (a 404 or capability response). A transient failure (timeout or 5xx) never causes a downgrade. The gateway retries with backoff and holds readings in a bounded queue. Every fallback increments a metric and logs a warning.
- **Phase 3, downgrade ratchet and cutover.** After one successful v2 handshake with a cloud, the gateway persists "v2 required" for that peer and refuses legacy from then on. This defends against an attacker who blocks v2 to force a downgrade. The suite list is in the signed transcript, so tampering is detected. The cloud sets a date `LEGACY_UNTIL`, after which `/v1` returns an error (410 or 426).
- **Phase 4, retire the static key.** Remove `SHARED_KEY` from the code, Compose and README, and rotate any secret that was ever used with legacy mode. Document key custody and the incident rotation procedure.

**Why no silent fallback.** The proposal doc forbids it. A fallback that is silent makes the migration look finished while traffic is still unprotected. The explicit allowlist, the metric, the date and the ratchet make it visible and time-limited.

## 3. Choice of ML-KEM parameter set

| Set | Encap key | Ciphertext | Shared secret | NIST category |
|---|---|---|---|---|
| ML-KEM-512 | 800 B | 768 B | 32 B | 1 (about AES-128) |
| ML-KEM-768 | 1184 B | 1088 B | 32 B | 3 (about AES-192) |
| ML-KEM-1024 | 1568 B | 1568 B | 32 B | 5 (about AES-256) |

**Decision: ML-KEM-768 by default, in hybrid with X25519.**

- It is the common default (for example the X25519MLKEM768 TLS group) and has the best interoperability.
- It has a wide margin over the best known attacks. The extra size and cost over 512 is negligible here.
- The handshake happens once per session (every few minutes or hours), and each reading is about 150 bytes. A 2 KB handshake does not matter on a gateway to cloud link, so the size argument for 512 does not apply.

**ML-KEM-1024 as an optional configured profile.** Use it for deployments with a higher assurance requirement (for example CNSA 2.0 policy, which mandates 1024) or long-lived data. The cost is about 30 to 50 percent more handshake bytes. It should be selectable by config and tested, but not the default.

**ML-KEM-512 is not enabled for gateway to cloud.** Category 1 is adequate in principle. The only argument for it is a constrained device link, which this design does not put ML-KEM on. Keep it testable (round-trip and size tests) so it is available if a future Cortex-M4 device performs ML-KEM itself. Otherwise reject it by policy.

**Implementation.** The suite name is a negotiated, allowlisted field (`suites`). The cloud chooses from its own allowlist, and the signed transcript prevents a downgrade between sets. A policy change then means a config change, not a code change.

## 4. Monitoring for ML-KEM

**Approach.** Extend the existing Prometheus text `/metrics` and use the `prometheus_client` library. It is a small, justified dependency, because labels and histograms are error-prone when hand-formatted. Move the duplicated metrics code into one shared helper.

**Cloud metrics:**

- `cloud_handshakes_total{mode,suite,result}`
- `cloud_handshake_failures_total{reason}`, with reasons: malformed, bad_length, unknown_suite, unknown_gateway, bad_confirm, replay, downgrade_attempt, policy_rejected
- `cloud_legacy_requests_total`, the main migration KPI
- `cloud_records_rejected_total{reason}` (replay, aead_fail, expired, unknown_session)
- `cloud_sessions_active` and `cloud_session_age_seconds`
- `cloud_handshake_duration_seconds` (histogram)
- `crypto_backend_info{library,version,suite} 1`, as a basic crypto inventory
- `crypto_selftest_ok`

**Gateway metrics:**

- `gateway_handshakes_total{result}`
- `gateway_rekeys_total`
- `gateway_fallback_total`, which should be zero after Phase 2
- `gateway_mode` (a gauge)
- `gateway_queue_depth`
- `gateway_handshake_duration_seconds`

**An ML-KEM-specific detail.** ML-KEM decapsulation uses implicit rejection: a bad ciphertext does not raise an error, it returns a pseudorandom secret. Monitoring must therefore watch for failed key confirmation and AEAD failures, not for decapsulation exceptions. This should be called out in the code and docs.

**Logging.** Use structured logs with the event, gateway_id, suite, a session_id prefix and the reason. Never log shared secrets, keys, ciphertexts or counters beyond what is needed.

**Alerts** (as Prometheus rule files):

- `cloud_legacy_requests_total` increasing after Phase 3
- `gateway_fallback_total` greater than 0
- handshake failure ratio above a threshold
- an AEAD failure spike
- `crypto_selftest_ok` equal to 0
- `cloud_sessions_active` approaching its cap

**Infrastructure.** Keep it small. Add an optional `monitoring` Compose profile with a single Prometheus container and a scrape config plus the rule file. Skip Grafana and Alertmanager for the sim, and document that production would add them. Metrics ports should not be published publicly.

## 5. Test design

Keep `unittest` and the existing `running_server` helper. Hypothesis is optional for fuzzing.

### A. Primitive tests

1. Round-trip for all three sets, with key, ciphertext and secret sizes checked against the table in section 3.
2. Known-answer decapsulation using NIST ACVP or FIPS 203 vectors. The liboqs-python API does not expose seeded key generation, so use fixed (secret key, ciphertext) to expected secret vectors.
3. Implicit rejection: a tampered ciphertext gives a different secret and no exception.
4. Differential test against kyber-py: a ciphertext made by liboqs must decapsulate to the same secret in kyber-py, and the other way round.
5. Combiner and KDF: changing any transcript field, nonce, suite or either secret changes the key. Labels are domain-separated.
6. AEAD: tampered ciphertext, AAD, counter or session_id fails. The nonce is never reused.

### B. Protocol and integration tests (cloud and gateway on loopback)

1. Happy path in hybrid mode: reading arrives, and the legacy counter stays at 0.
2. Existing legacy tests keep passing in legacy mode.
3. Mode matrix: legacy gateway against hybrid cloud, with legacy allowed and not allowed. Hybrid gateway against a legacy-only cloud, covering the fallback and the ratchet.
4. Downgrade: tamper with the `suites` list (the transcript signature fails), strip v2 after the ratchet is set (refused), and a transient 5xx (retry, no fallback).
5. Impersonation: wrong pinned cloud key, unknown gateway_id, wrong enrollment MAC.
6. Replay: a replayed handshake init, and a replayed or reordered record counter.
7. Malformed input: truncated or oversized `mlkem_ek`, wrong ciphertext length, invalid base64, unknown suite, missing fields, a body over 64 KB. All must return 4xx, never 500, and never crash a handler thread.
8. Rotation: a session expires by age or record count, the old session is rejected, and the gateway rekeys without data loss.
9. Recovery: restart the cloud in the middle of a run. The gateway re-handshakes, and queued readings are delivered.
10. Resource limits: the session table cap, and handshake rate limiting per gateway.

### C. Monitoring tests

- Each scenario above increments the expected metric.
- `/metrics` and the logs never contain key material (grep for the test secrets).

### D. Fuzz and size/performance

- Hypothesis fuzzing of the handshake parser, targeting no crashes and no state growth.
- Record handshake bytes and time per parameter set, and assert a size budget in a test.

### E. CI and end-to-end

- The CI image must build liboqs. Tests that need it use a skip marker, but CI sets `REQUIRE_PQ=1` so they fail instead of skipping when the backend is missing.
- A Compose smoke test: bring the stack up, wait for a reading, and assert that the handshake succeeded and `cloud_legacy_requests_total` is 0.
- Add an image scan and an SBOM to the build, which the README says the CI currently lacks.

## 6. Wider network infrastructure changes

**Topology.** Split the current single Compose network into a device-net (device and gateway) and a cloud-net (gateway and cloud). The cloud then cannot reach the sensor directly, and the device stays isolated. Real deployments add a physical or serial/LoRa/BLE link between sensor and gateway, and a WAN between gateway and cloud.

**Ingress.** Put a TLS-terminating reverse proxy or API gateway in front of the cloud in production. With a recent OpenSSL (3.5 or later), it can do TLS 1.3 hybrid key exchange itself. App-layer ML-KEM then protects the payload end to end behind it (defense in depth) until a TLS-only design is trusted.

**Packet size.** A hybrid ML-KEM-768 TLS ClientHello is larger than 1.2 KB and may span more than one packet. Some old firewalls and middleboxes mishandle it, so test through any real middlebox. UDP and QUIC paths need MTU testing for the same reason.

**Sessions and scaling.** Sessions live in memory in one cloud process. Several cloud replicas would need sticky routing, a shared session store, or stateless session tickets. For the sim, stay on a single instance and document the limit.

**Key management.**

- The cloud identity key belongs in a secret manager, KMS or HSM, with a rotation procedure.
- The gateway needs an enrollment and revocation process and a registry of gateways.
- Trust-anchor distribution to gateways must be defined.
- Public CAs do not yet issue PQ certificates, so production would use a private CA.

**Time and entropy.** Session expiry and replay logic depend on reasonable clocks (NTP on the gateway). ML-KEM and X25519 need good randomness, which embedded boards do not always provide without a hardware RNG.

**Handshake abuse.** An unauthenticated handshake endpoint must not allocate unbounded state. Authenticate the gateway before creating a session, rate limit per gateway_id and cap the table.

**Observability network.** Prometheus needs to reach `/metrics` on both services, and the metrics endpoint should not be exposed publicly. Remove the published ports for 8080 and 8081 from any production config.

**Supply chain and CI/CD.** The pipeline now builds a native library: pin and verify its checksum, keep an SBOM, and scan the image. Rebuild and redeploy promptly when liboqs ships a security fix.

**Firmware.** If devices become updatable, sign firmware with a stateful hash-based scheme such as LMS or XMSS. These are small, conservative and standardized (NIST SP 800-208), and they fit constrained devices.

**Compliance.** Keep a cryptographic inventory (the `crypto_backend_info` metric helps). NIST IR 8547 plans to deprecate RSA and ECC by 2030 and disallow them by 2035. That is the schedule the `LEGACY_UNTIL` date should respect.

**Data at rest.** The cloud store is in memory, so nothing persistent is exposed. Any future database or backup is exposed to "harvest now, decrypt later" and needs its own encryption plan.

## 7. Alternatives to the Python libraries

**Network-level approaches (no application changes):**

- TLS 1.3 with the hybrid X25519MLKEM768 group, using OpenSSL 3.5 or later, or oqs-provider on older OpenSSL. Python's `ssl` module would use whatever OpenSSL it links. nginx, HAProxy, Envoy, Caddy and Go (1.24 and later) support it. nginx also exposes the negotiated curve in its logs for monitoring. This is the production target.
- PQ VPN or tunnel between gateway and cloud: OpenSSH 9.x hybrid KEX (sntrup761x25519, or mlkem768x25519 in newer versions), strongSwan with IKEv2 multiple key exchanges (RFC 9370), or Rosenpass with WireGuard.

**Other ML-KEM implementations (via sidecar, cffi or ctypes):**

- Go standard library `crypto/mlkem`.
- Rust crates: RustCrypto `ml-kem`, and libcrux (formally verified).
- C libraries: mlkem-native (PQCA, with verification work), PQClean, and AWS-LC (aws-lc-rs for Rust).
- Java (Bouncy Castle) and OS APIs (Windows CNG, Apple CryptoKit).
- Embedded: pqm4 for Cortex-M4 and wolfSSL's wolfCrypt. These are the options if a device ever has to run ML-KEM itself.
- Pure Python: kyber-py, for tests only.

**Other post-quantum KEMs:**

- HQC, chosen by NIST in 2025 as a code-based backup to ML-KEM. Check the standardization status.
- Classic McEliece: very conservative, but public keys are hundreds of KB.
- FrodoKEM: unstructured lattice, conservative, with larger keys.
- NTRU and NTRU Prime: sntrup761 is already used by OpenSSH.
- BIKE.

**PQ signatures** (for identities and firmware):

- ML-DSA (FIPS 204), a good fit for replacing Ed25519 in this design.
- SLH-DSA (FIPS 205), hash-based and conservative, but with larger signatures.
- FN-DSA (Falcon, FIPS 206), whose standard status should be checked.
- LMS and XMSS for firmware signing.

**Symmetric-only approach.** For a closed fleet that can provision secrets, improve the current design with per-device 256-bit keys, HKDF-derived session keys, ratcheting and rotation. It is quantum-safe without any PQ library. The cost is manual key provisioning and no open-ended negotiation. This is a valid fallback if liboqs turns out to be too heavy for the project, and it is already the device link design in section 2.

**Not recommended:** QKD, which needs special hardware and is not practical here.

## Suggested order of work

1. Phase 0: shared metrics helper, new metrics, tests for them.
2. Library and build changes: dependency lock, multi-stage Dockerfile, `sdmo/crypto.py`, self-test, primitive tests (A).
3. Cloud `/v2` handshake and records with the session table.
4. Gateway `Session` object, retry and queue, hybrid mode, protocol tests (B).
5. Device MAC and per-device key (optional flag).
6. Fallback policy, ratchet, `LEGACY_UNTIL`, mode-matrix tests.
7. Network split, optional Prometheus profile and alert rules, Compose smoke test and CI changes.
8. Remove the static key, update the README and `docs/ml-kem-migration.md`, and write the key custody and rotation notes.

## Points to confirm before implementation

- Whether liboqs-python builds on Python 3.14 in the container. If not, pin the interpreter to the newest version it supports.
- Whether pyca/cryptography has since added ML-KEM, which would remove the native build.
- The current status of HQC and FN-DSA, since both were still moving when this plan was written.
