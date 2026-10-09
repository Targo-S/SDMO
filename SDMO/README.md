# SDMO Device-to-Cloud Starter

Three small Python services: a simulated legacy sensor, an edge gateway that polls and forwards readings, and a cloud HTTP service with in-memory storage.

## Run

Requirements: Docker with the Compose plugin.

```sh
docker compose up --build
```

The gateway polls every five seconds. Readings: `http://localhost:8081/v1/readings`. Cloud and gateway metrics: `http://localhost:8081/metrics` and `http://localhost:8080/metrics`. Each service exposes `/healthz`; the device is only reachable inside Compose.

Run tests without Docker on Windows:

```powershell
py -m unittest discover -s tests -v
```

## Intentional Baseline Gaps

- Cloud readings are in memory and lost on restart; gateway polling has no durable queue or retry backoff.
- Gateway/cloud authentication uses a long-lived, static shared key over plain HTTP. The Compose default is demo-only and not suitable for production.
- Monitoring is limited to health endpoints and a few counters: no collector, dashboards, alerts, tracing, or centralized logs.
- CI tests and builds an image; a separate workflow publishes it to GHCR and a test deployment runs health checks (see Test Deployment). There is no scanning or production deploy. Test coverage is deliberately narrow.
- The ML-KEM document is a proposal only; no cryptography is implemented. See [docs/ml-kem-migration.md](docs/ml-kem-migration.md).

Set `SHARED_KEY` before starting Compose to replace the demo value. Do not use this starter with real devices or production data.

## Test Deployment

`.github/workflows/deploy-test.yml` ("Deploy Test") is separate from build/publish CI. It does not rebuild: it pulls the image published to GHCR by the `Docker` workflow and starts the stack with `compose.yaml` + `compose.test.yaml` on the Actions runner (an ephemeral test environment). It then runs `scripts/check_health.sh`, which polls `/healthz` for the gateway (8080) and cloud (8081) services; the legacy device (8082) is covered by its container healthcheck, which the gateway depends on. The workflow fails if anything is unhealthy.

- **When it runs:** automatically after a successful `Docker` workflow run triggered by a push to `main`; never for pull requests, forks or schedules.
- **Manual trigger:** Actions > Deploy Test > Run workflow, optionally with an `image_tag` (default `main`; version tags like `0.1.0` also work).
- **Config:** uses the `test` GitHub environment (optionally add protection rules) and the optional secret `SDMO_SHARED_KEY` (defaults to the demo key). `GITHUB_TOKEN` is used to pull the image.
- **Locally:** `SDMO_IMAGE=ghcr.io/<owner>/<repo>:main docker compose -f compose.yaml -f compose.test.yaml up -d --wait && ./scripts/check_health.sh`
# SDMO Device-to-Cloud Starter

Three small Python services: a simulated legacy sensor, an edge gateway that polls and forwards readings, and a cloud HTTP service with in-memory storage. The gateway and cloud establish sessions with a hybrid X25519 + ML-KEM-768 handshake; see [docs/ml-kem-infrastructure-plan.md](docs/ml-kem-infrastructure-plan.md).

## Run

Requirements: Docker with the Compose plugin.

```sh
docker compose up --build
```

A one-shot `provision` service creates the cloud identity key, the gateway enrollment secret and the device key in a Compose volume. The cloud accepts only hybrid sessions (`ACCEPT_MODES=hybrid`) and the gateway never falls back to the static key (`ALLOW_LEGACY_FALLBACK=false`).

The gateway polls every five seconds. Readings: `http://localhost:8081/v1/readings`. Cloud and gateway metrics: `http://localhost:8081/metrics` and `http://localhost:8080/metrics`. Each service exposes `/healthz`; the device is only reachable on the device network inside Compose.

Optional Prometheus with the ML-KEM alert rules: `docker compose --profile monitoring up --build`, then `http://localhost:9090`.

Run tests without Docker on Windows:

```powershell
py -m pip install -r requirements-dev.txt
py -m unittest discover -s tests -v
```

## ML-KEM Design

- Library: `cryptography` (pyca) provides ML-KEM-768 and ML-KEM-1024, X25519, Ed25519, HKDF-SHA256 and ChaCha20-Poly1305 from one maintained dependency, with no native build step. `kyber-py` is used only as an independent test oracle.
- Handshake (`POST /v2/handshake`): ephemeral X25519 + ML-KEM-768 secrets are combined with HKDF over the full transcript. The gateway authenticates with an HMAC keyed by its enrollment secret; the cloud signs the transcript with an Ed25519 key the gateway pins. Records (`POST /v2/readings`) are AEAD-protected with a strictly increasing counter. ML-KEM-1024 is selectable through `KEM_SUITES`; ML-KEM-512 is not offered.
- Device link: the sensor stays classical. When `DEVICE_MASTER_FILE` is set it adds an HMAC (per-device key) to each frame and the gateway verifies it.
- Migration modes: the cloud's `ACCEPT_MODES` (`legacy`, `hybrid`) and `LEGACY_UNTIL` retire `/v1`. The gateway's `PREFERRED_MODE` (`legacy` default, `hybrid`) and `ALLOW_LEGACY_FALLBACK` only permit a fallback when the cloud has no `/v2`; a transient failure queues and retries instead. After one successful v2 handshake the gateway records a downgrade ratchet (`RATCHET_FILE`) and refuses the static key for that cloud.
- Monitoring: `cloud_legacy_requests_total`, `cloud_handshakes_total`, `cloud_handshake_failures_total`, `cloud_records_rejected_total`, `gateway_fallback_total`, `crypto_selftest_ok`, `crypto_backend_info` and more. Decapsulation uses implicit rejection, so bad ciphertexts surface as failed key confirmation or AEAD checks.

Run the services without Compose by setting the environment variables shown in [compose.yaml](compose.yaml) and creating keys with `python -m sdmo.provision DIR [GATEWAY_ID]`. For a dual-stack cloud, set `ACCEPT_MODES=legacy,hybrid` and `SHARED_KEY`.

## Intentional Baseline Gaps

- Cloud readings are in memory and lost on restart; the gateway queue is in memory, bounded and drops the oldest reading when full.
- The `/v2` protocol is a simulation stand-in for TLS 1.3 hybrid key exchange. It travels over plain HTTP, the cloud identity is Ed25519 (not post-quantum), sessions are held in one process's memory, and secrets live in a shared Compose volume. Do not use it in production.
- The legacy static-key path (`SHARED_KEY`, `/v1/readings`) is still in the code for the migration phases; removing it is the last step once `cloud_legacy_requests_total` stays at zero.
- The device MAC does not reject replayed sequence numbers, because the simulated device restarts its counter at 1.
- Monitoring is Prometheus text endpoints plus an optional single Prometheus container: no dashboards, Alertmanager, tracing, or centralized logs.
- CI tests and builds an image but does not publish, scan, release, or deploy it. Dependencies are pinned in `requirements.txt` without hashes.

Do not use this starter with real devices or production data.
