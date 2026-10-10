import json
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from sdmo.cloud import CloudState, make_handler


@pytest.fixture
def cloud_server():
    state = CloudState(shared_key="test-key")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield state, f"http://{host}:{port}"
    server.shutdown()


def _post(url, payload, key="test-key"):
    request = Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Legacy-Shared-Key": key},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def _reading(**overrides):
    base = {
        "device_id": "legacy-sensor-01",
        "sequence": 1,
        "temperature_c": 21.5,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    base.update(overrides)
    return base


# --- Type validation ---

def test_rejects_string_temperature(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(temperature_c="orange"))
    assert status == 400


def test_rejects_string_sequence(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(sequence="hello"))
    assert status == 400


def test_rejects_non_string_device_id(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(device_id=12345))
    assert status == 400


def test_rejects_missing_field(cloud_server):
    _, url = cloud_server
    payload = _reading()
    del payload["observed_at"]
    status, _ = _post(url + "/v1/readings", payload)
    assert status == 400


def test_rejects_bool_temperature(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(temperature_c=True))
    assert status == 400


def test_rejects_bool_sequence(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(sequence=True))
    assert status == 400


def test_rejects_negative_sequence(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(sequence=-1))
    assert status == 400


def test_rejects_zero_sequence(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(sequence=0))
    assert status == 400


def test_rejects_out_of_range_temperature_high(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(temperature_c=999.0))
    assert status == 400


def test_rejects_out_of_range_temperature_low(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(temperature_c=-200.0))
    assert status == 400


def test_rejects_naive_timestamp(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(observed_at="2026-10-08T20:00:00"))
    assert status == 400


def test_rejects_non_iso_timestamp(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(observed_at="yesterday"))
    assert status == 400


def test_rejects_future_timestamp(cloud_server):
    _, url = cloud_server
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    status, _ = _post(url + "/v1/readings", _reading(observed_at=future))
    assert status == 400


def test_rejects_too_old_timestamp(cloud_server):
    _, url = cloud_server
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    status, _ = _post(url + "/v1/readings", _reading(observed_at=old))
    assert status == 400


def test_rejects_overlong_device_id(cloud_server):
    _, url = cloud_server
    status, _ = _post(url + "/v1/readings", _reading(device_id="x" * 100))
    assert status == 400


# --- Replay protection ---

def test_rejects_duplicate_sequence(cloud_server):
    _, url = cloud_server
    payload = _reading()
    status1, _ = _post(url + "/v1/readings", payload)
    assert status1 == 202
    status2, body2 = _post(url + "/v1/readings", payload)
    assert status2 == 409
    assert body2["error"] == "duplicate sequence"


def test_accepts_different_sequences(cloud_server):
    _, url = cloud_server
    status1, _ = _post(url + "/v1/readings", _reading(sequence=1))
    status2, _ = _post(url + "/v1/readings", _reading(sequence=2))
    assert status1 == 202
    assert status2 == 202


def test_accepts_same_sequence_from_different_device(cloud_server):
    _, url = cloud_server
    status1, _ = _post(url + "/v1/readings", _reading(device_id="device-A", sequence=1))
    status2, _ = _post(url + "/v1/readings", _reading(device_id="device-B", sequence=1))
    assert status1 == 202
    assert status2 == 202


# --- Happy path ---

def test_accepts_valid_reading(cloud_server):
    state, url = cloud_server
    status, body = _post(url + "/v1/readings", _reading())
    assert status == 202
    assert body == {"accepted": True}
    assert len(state.readings) == 1


def test_rejected_counter_increments(cloud_server):
    state, url = cloud_server
    _post(url + "/v1/readings", _reading(temperature_c="orange"))
    _post(url + "/v1/readings", _reading(sequence="hello"))
    assert state.rejected >= 2