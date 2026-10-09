# ML-KEM Implementation Notes

What was added to the SDMO simulation to implement the plan in [ml-kem-infrastructure-plan.md](ml-kem-infrastructure-plan.md). The older proposal and plan documents are unchanged and describe intent; this file describes what exists in the code.

This is a simulation. The `/v2` protocol is a stand-in for TLS 1.3 hybrid key exchange and must not be used with real devices or production data.

## Summary

- Gateway to cloud sessions are established with a hybrid X25519 + ML-KEM-768 handshake. Records are protected with ChaCha20-Poly1305.
- The legacy static-key path (`/v1/readings`, `SHARED_KEY`) still exists so the migration can be staged and measured. Phases 0 to 3 of the plan are implemented. Phase 4 (deleting the static-key code) is not done.
- The sensor link stays classical: an optional per-device HMAC on each reading.
- Compose now runs hybrid-only with no static-key fallback.

## Library choice

`cryptography` (pyca) 50.0.2 is the only runtime crypto dependency. It provides ML-KEM-768, ML-KEM-1024, X25519, Ed25519, HKDF-SHA256 and ChaCha20-Poly1305.

The plan recommended liboqs-python and said pyca/cryptography should become the preferred backend if it exposed ML-KEM. It does, so it is used. Compared with liboqs-python this gives one pip dependency, wheels for Python 3.14, and no native build, so the Dockerfile stays single-stage.

- ML-KEM-512 is not provided by the backend and is excluded by policy.
- `kyber-py` (pure Python, not constant-time) is a test-only oracle for differential tests. It is listed in `requirements-dev.txt` and the `test` extra, not in the runtime image.
- `prometheus-client` provides labelled counters and histograms for the metrics endpoints.

## Parameter sets

| Suite name | Encapsulation key | Ciphertext | Default |
|---|---|---|---|
| `X25519+ML-KEM-768` | 1184 B | 1088 B | yes |
| `X25519+ML-KEM-1024` | 1568 B | 1568 B | no, opt-in |

The suite is an allowlisted config value: `KEM_SUITES` on the cloud (policy) and the gateway (ordered preference). Anything else is rejected.

## New and changed files

| File | Role |
|---|---|
| `sdmo/crypto.py` | Suites, KEM wrappers, base64 and field encoding, request MAC, transcript hash, Ed25519 transcript signature, HKDF key derivation, record seal and open, ack and confirm tags, device frame MAC, self-test |
| `sdmo/kat.json` | Known-answer vectors used by the self-test |
| `sdmo/metrics.py` | Shared `/metrics` response helper and crypto inventory and self-test registration |
| `sdmo/cloud.py` | `CloudState` (sessions, registry, limits, metrics), `/v2/handshake`, `/v2/readings`, legacy retirement, config from environment |
| `sdmo/gateway.py` | `HybridClient`, `Forwarder`, `Ratchet`, bounded queue with backoff, `GatewayMetrics`, config from environment. `poll_once()` keeps its legacy behaviour |
| `sdmo/legacy_device.py` | Optional per-device HMAC on readings |
| `sdmo/provision.py` | Creates keys and secrets; never overwrites existing files |
| `tests/helpers.py`, `tests/test_crypto.py`, `tests/test_hybrid.py` | New tests. `tests/test_pipeline.py` now imports its server helper from `tests/helpers.py` |
| `Dockerfile`, `compose.yaml`, `requirements.txt`, `requirements-dev.txt`, `pyproject.toml` | Dependencies, provisioning, network split, state volume |
| `monitoring/prometheus.yml`, `monitoring/alerts.yml` | Optional Prometheus scrape config and alert rules |

## Protocol

All bodies are JSON. Binary fields are base64url without padding and are decoded strictly (alphabet, length). Request bodies are limited to 64 KB by `read_json()`.

### Handshake: `POST /v2/handshake`

Request: `v` (2), `gateway_id`, `suite`, `mlkem_ek` (ephemeral encapsulation key), `x25519`, `nonce` (16 B), `timestamp` (integer seconds), `mac`.

1. `mac` is HMAC-SHA256 over the other fields, keyed with the gateway's enrollment secret. The cloud checks it before doing any KEM work or allocating state.
2. The cloud rejects timestamps more than 60 s from its clock and repeated `(gateway_id, nonce)` pairs, then applies the handshake rate limit and session caps.
3. The cloud encapsulates to `mlkem_ek`, performs an X25519 exchange, and derives keys with HKDF-SHA256. The input is `ss_pq || ss_ec`, the salt is `nonce_g || nonce_c`, and the info is a label plus the SHA-256 transcript hash. The transcript covers the gateway id, suite, `mlkem_ek`, both X25519 keys, both nonces, the timestamp, the ciphertext and the session id.
4. Response (HTTP 200): `v`, `session_id`, `suite`, `ct`, `x25519`, `nonce`, `signature` (Ed25519 over the transcript hash with a domain label), `confirm` (HMAC of the transcript under the derived MAC key).
5. The gateway checks that the suite and version are unchanged, verifies the signature against the pinned cloud public key, decapsulates, derives the same keys and checks `confirm`. Any failure raises `HandshakeError` and no session is kept.

Two keys come out of the KDF: a gateway-to-cloud record key and a cloud-to-gateway MAC key (used for `confirm` and record acknowledgements).

The session starts pending (30 s lifetime). The first authentic record from the gateway is its key confirmation and makes the session active.

### Records: `POST /v2/readings`

Request: `session_id`, `counter`, `ciphertext`. The plaintext is the reading JSON. The nonce is the 64-bit counter as a 12-byte big-endian value, and the AAD is the session id plus the counter. The counter must strictly increase; the gateway burns a counter even when a request fails, so nonces are never reused.

Response (HTTP 202): `accepted`, `counter`, `ack`. The `ack` is an HMAC under the MAC key; the gateway rejects a missing or wrong one.

A session ends after 3600 s or 10,000 records on the cloud. The gateway rekeys earlier by default (1800 s or 5000 records). A `401` on a record makes the gateway handshake again and retry once.

### Status codes

| Code | Meaning |
|---|---|
| 200 / 202 | Handshake / record accepted |
| 400 | Malformed input, bad version, unsupported suite (lists supported suites), invalid reading |
| 401 | Any authentication, replay, expiry or unknown-session failure. The body is always the generic `unauthorized`; the real reason appears only in metrics |
| 404 | `/v2` absent (cloud not in hybrid mode). The gateway reads this as "cloud has no v2" |
| 410 | `/v1` retired (legacy not accepted, or past `LEGACY_UNTIL`) |
| 429 / 503 | Handshake rate limit / session table full |

### Cloud limits (constructor defaults of `CloudState`)

Session lifetime 3600 s, record limit 10,000, pending lifetime 30 s, 1024 sessions in total, 4 per gateway (oldest evicted), 30 handshakes per minute per gateway, clock skew 60 s, nonce replay cache of 4096 entries.

## Migration modes and fallback

- **Cloud `ACCEPT_MODES`:** `legacy`, `hybrid` or both. `LEGACY_UNTIL` (ISO 8601) turns `/v1` into `410` after that time. Every `/v1` POST increments `cloud_legacy_requests_total`; in dual-stack mode it also logs a deprecation line.
- **Gateway `PREFERRED_MODE`:** `legacy` (default, original behaviour) or `hybrid`.
- **Fallback:** with `ALLOW_LEGACY_FALLBACK=true` (needs `SHARED_KEY`) the gateway uses the static key only when the cloud answers 404 to the handshake. Each fallback increments `gateway_fallback_total` and logs a warning. Timeouts, 5xx responses and rejected handshakes never downgrade: the reading stays queued and is retried.
- **Downgrade ratchet:** after one successful v2 delivery to a cloud, the gateway records it (`RATCHET_FILE`, keyed by the cloud base URL) and refuses the static key for that cloud from then on, including after a restart.
- **Queue:** the gateway keeps readings in a bounded in-memory queue (`QUEUE_SIZE`, default 1000; oldest dropped and counted). Delivery stops at the first failure and the poll loop backs off exponentially up to 60 s.

Compose defaults: cloud `ACCEPT_MODES=hybrid`, gateway `PREFERRED_MODE=hybrid`, `ALLOW_LEGACY_FALLBACK=false`.

## Sensor link

If `DEVICE_MASTER_FILE` is set, the device adds `mac` to each reading: HMAC-SHA256 over the canonical JSON, keyed with a key derived from the master secret and the device id (HKDF-SHA256). The gateway, given the same file, verifies and strips the MAC. A missing or wrong MAC raises `DeviceAuthError`, counts `gateway_device_auth_failures_total` and discards the reading. The device still speaks plain HTTP in the simulation; a real Arduino would implement the same MAC.

The gateway is the post-quantum termination point. This means device-to-cloud confidentiality is not end to end.

## Configuration reference

Key and secret files hold hex text. Create them with `python -m sdmo.provision DIR [GATEWAY_ID ...]` (default `gateway-01`), which writes `cloud_identity.key`, `cloud_identity.pub`, `registry.json`, `<gateway>.secret` and `device_master.secret`. Compose does this with a one-shot `provision` service writing to a shared volume.

Cloud:

| Variable | Default | Purpose |
|---|---|---|
| `CLOUD_PORT` | `8081` | Listen port |
| `ACCEPT_MODES` | `legacy,hybrid` if an identity key is set, else `legacy` | Accepted modes |
| `SHARED_KEY` | `demo-only-change-me` | Static key, used only if `legacy` is accepted |
| `CLOUD_IDENTITY_KEY_FILE` | unset | Ed25519 seed; enables hybrid |
| `GATEWAY_REGISTRY_FILE` | required with the identity key | JSON map of gateway id to enrollment secret |
| `KEM_SUITES` | `X25519+ML-KEM-768` | Allowed suites |
| `LEGACY_UNTIL` | unset | Retirement time for `/v1` |

Gateway:

| Variable | Default | Purpose |
|---|---|---|
| `DEVICE_URL`, `CLOUD_URL`, `GATEWAY_PORT`, `POLL_SECONDS` | as before | Unchanged |
| `CLOUD_BASE_URL` | scheme and host of `CLOUD_URL` | Base for `/v2` calls |
| `PREFERRED_MODE` | `legacy` | `legacy` or `hybrid` |
| `ALLOW_LEGACY_FALLBACK` | `false` | Permit fallback when the cloud has no v2 |
| `SHARED_KEY` | demo value in legacy mode only | Static key for legacy or fallback |
| `GATEWAY_ID` | `gateway-01` | Identity presented to the cloud |
| `ENROLLMENT_SECRET_FILE` | required in hybrid mode | Enrollment secret |
| `CLOUD_IDENTITY_PUB_FILE` | required in hybrid mode | Pinned Ed25519 public key |
| `KEM_SUITES` | `X25519+ML-KEM-768` | Ordered preference |
| `REKEY_SECONDS`, `REKEY_RECORDS` | `1800`, `5000` | Proactive rekey thresholds |
| `QUEUE_SIZE` | `1000` | Queue bound |
| `RATCHET_FILE` | unset (memory only) | Persisted downgrade ratchet |
| `DEVICE_MASTER_FILE` | unset | Verify device frame MACs |

Device: `DEVICE_ID`, `DEVICE_PORT` (unchanged) and `DEVICE_MASTER_FILE` (adds the MAC).

## Monitoring

Both services serve Prometheus text at `/metrics`. The original names `gateway_forwarded_total`, `gateway_errors_total`, `cloud_received_readings` and `cloud_rejected_requests` are kept.

Cloud:

- `cloud_handshakes_total{mode,suite,result}`
- `cloud_handshake_failures_total{reason}`: `malformed`, `bad_version`, `unknown_gateway`, `unsupported_suite`, `bad_mac`, `stale_timestamp`, `replay`, `rate_limited`, `capacity`
- `cloud_records_rejected_total{reason}`: `malformed`, `unknown_session`, `expired`, `replay`, `aead_fail`, `invalid_reading`
- `cloud_legacy_requests_total` (the migration indicator; it should stay at zero once the migration is done)
- `cloud_sessions_active`, `cloud_session_age_seconds` (expired sessions are excluded)
- `cloud_handshake_duration_seconds` (histogram)

Gateway:

- `gateway_handshakes_total{result}` (`ok`, `unsupported`, `rejected`, `error`)
- `gateway_rekeys_total`, `gateway_fallback_total`, `gateway_dropped_total`, `gateway_device_auth_failures_total`
- `gateway_queue_depth`, `gateway_mode` (0 legacy, 1 hybrid), `gateway_handshake_duration_seconds`

Both, when hybrid is enabled: `crypto_backend_info{library,version,suites}` and `crypto_selftest_ok`.

ML-KEM decapsulation uses implicit rejection: a forged ciphertext produces a different secret rather than an error. Such failures therefore show up as failed key confirmation, `bad_mac`-style handshake errors or `aead_fail`, not as decapsulation exceptions.

Logging: handlers print request lines, deprecation and fallback warnings and delivery errors. Keys, secrets and ciphertexts are never logged; a test checks this.

Optional Prometheus: `docker compose --profile monitoring up --build`, then `http://localhost:9090`. `monitoring/alerts.yml` defines: legacy key still in use, gateway fell back to the static key, handshake failure ratio above 20%, record authentication failures, self-test failed, session table above 800 entries.

## Startup self-test

At startup each hybrid-enabled process runs `crypto.selftest()` and exits if it fails. For each suite it checks:

1. Key generation from a fixed seed against a pinned public-key hash.
2. Decapsulation of a pinned ciphertext against the expected secret.
3. An encapsulate and decapsulate round trip.

The vectors in `sdmo/kat.json` were generated with `kyber-py` and cross-checked against `cryptography`. They are a regression and cross-implementation check, not the official NIST ACVP set.

## Tests

Run: `py -m pip install -r requirements-dev.txt` then `py -m unittest discover -s tests -v`. There are 76 tests (about 4 s); the two original tests still pass.

- **Primitives:** round trip and sizes for both suites, implicit rejection, wrong lengths, self-test and corruption detection, differential tests against `kyber-py` (skipped if it is not installed), KDF input sensitivity and domain separation, transcript binding, record tamper detection, strict base64, ack binding, device MAC.
- **Flow and migration:** hybrid delivery with the legacy counter at zero, session reuse, 1024 suite, suite retry, forged acks, hybrid-only cloud rejecting `/v1`, `LEGACY_UNTIL`, invalid configuration, fallback allowed and disallowed, ratchet blocking fallback and surviving restart, a 5xx never downgrading.
- **Attacks:** every tampered handshake response field, modified requests, in-flight suite downgrade, wrong pinned key, unknown gateway, wrong enrollment secret, replayed handshakes, stale and future timestamps, replayed and reordered records, cross-session records, invalid readings.
- **Malformed input:** about thirty bad handshake and record bodies, including an oversized body, a low-order X25519 point and a garbage encapsulation key. All must return 4xx or 200, never 5xx, and the server must stay healthy.
- **Rotation, recovery and limits:** expiry by age and record count on both sides, fresh keys per session, lost sessions, queued readings after an outage, queue overflow, session caps, rate limit, pending expiry.
- **Monitoring:** metrics exposed, self-test failure stops startup, secrets absent from metrics and logs.
- **Fuzz and size:** seeded random mutation of handshakes and records (no crash, no state created), handshake byte budget per suite.
- **Wiring:** provisioning is idempotent; services built from environment variables deliver a reading; device frames verified end to end.

## Verification performed

- All 76 tests pass.
- Device, cloud and gateway were run as local processes with provisioned keys: readings flowed, the handshake count was 1, legacy requests were 0, the self-test gauge was 1, a static-key POST returned 410, and the ratchet file was written.
- The Compose stack was not started because the Docker daemon was not available; `docker compose config` validates.

## Differences from the plan

- Backend is pyca/cryptography instead of liboqs-python (see above). No backend selection by config, no multi-stage Dockerfile and no `requirements.lock` with hashes.
- The handshake carries one `suite` chosen by the gateway (ordered preference with retry on `unsupported_suite`) rather than a list. The suite is covered by both the request MAC and the signed transcript.
- Gateway authentication is a request MAC checked before any KEM work, not a MAC over the full transcript. Key confirmation from the gateway is the first authentic record.
- Only the gateway-to-cloud direction is encrypted; cloud responses carry a MAC.
- `pq-only` mode is not implemented.
- The device uses `DEVICE_MASTER_FILE`, not `DEVICE_KEY`. The gateway does not assign `observed_at`.
- Secrets live in a shared Compose volume, not Docker secrets.
- Fuzzing uses a seeded mutator, not Hypothesis.
- No CI changes, image scan or SBOM.

## Known limitations

- Plain HTTP; the `/v2` protocol replaces TLS only for this simulation.
- The cloud identity is Ed25519, which is not post-quantum. ML-DSA-65 is available in the same library as a later swap.
- Sessions, readings and the gateway queue are in memory in a single process.
- The device MAC covers the sequence number, but the gateway does not reject replays because the simulated device restarts its counter at 1.
- Published ports 8080 and 8081 remain for the simulation and should be removed in any real deployment.
- Dependencies are pinned in `requirements.txt` without hashes.
