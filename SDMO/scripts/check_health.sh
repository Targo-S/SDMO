#!/usr/bin/env bash
# Poll the /healthz endpoints of the gateway, cloud and legacy services.
# Usage: check_health.sh [host] [timeout_seconds]
set -u
host="${1:-localhost}"
timeout="${2:-60}"
# legacy device (8082) is not published by compose; it is covered by the
# container healthcheck that gateway depends on.
urls=("http://${host}:8080/healthz" "http://${host}:8081/healthz")
for url in "${urls[@]}"; do
  deadline=$((SECONDS + timeout))
  until curl -fsS --max-time 3 "$url" >/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "UNHEALTHY: $url" >&2
      exit 1
    fi
    sleep 2
  done
  echo "healthy: $url"
done
