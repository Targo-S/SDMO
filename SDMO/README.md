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
