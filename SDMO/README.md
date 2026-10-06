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
- CI tests and builds an image but does not publish, scan, release, or deploy it. Test coverage is deliberately narrow.
- The ML-KEM document is a proposal only; no cryptography is implemented. See [docs/ml-kem-migration.md](docs/ml-kem-migration.md).

Set `SHARED_KEY` before starting Compose to replace the demo value. Do not use this starter with real devices or production data.
