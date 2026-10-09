"""Cloud service: input validation, authentication, replay protection and
health/metrics endpoints. Each test states the required behaviour."""
import json
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from sdmo.cloud import CloudState, make_handler
from tests.helpers import (
    KEY,
    post_reading,
    raw_post,
    running_server,
    setUpModule,  # noqa: F401
    tearDownModule,
    valid_reading,
)


class CloudValidationTests(unittest.TestCase):
    def assert_rejected(self, reading):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            status = post_reading(cloud, reading)
        self.assertEqual(status, 400)
        self.assertEqual(state.readings, [])

    def assert_raw_rejected(self, body, headers):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            status = raw_post(cloud, body, {"X-Legacy-Shared-Key": KEY, **headers})
        self.assertEqual(status, 400)
        self.assertEqual(state.readings, [])

    def test_accepts_valid_reading(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            self.assertEqual(post_reading(cloud, valid_reading()), 202)
        self.assertEqual(state.readings, [valid_reading()])

    def test_rejects_each_missing_required_field(self):
        for field in ("device_id", "sequence", "temperature_c", "observed_at"):
            with self.subTest(field=field):
                reading = valid_reading()
                del reading[field]
                self.assert_rejected(reading)

    # Malformed bodies and headers
    def test_rejects_invalid_json(self):
        self.assert_raw_rejected(b"{not json", {"Content-Length": "9"})

    def test_rejects_non_utf8_body(self):
        self.assert_raw_rejected(b"\xff\xfe\xfa", {"Content-Length": "3"})

    def test_rejects_json_array_body(self):
        self.assert_raw_rejected(b"[1, 2]", {"Content-Length": "6"})

    def test_rejects_missing_content_length(self):
        self.assert_raw_rejected(b"", {})

    def test_rejects_non_numeric_content_length(self):
        self.assert_raw_rejected(b"{}", {"Content-Length": "abc"})

    def test_rejects_negative_content_length(self):
        self.assert_raw_rejected(b"{}", {"Content-Length": "-5"})

    def test_rejects_oversized_body(self):
        # Size is checked before reading, so a short body with a large header is enough.
        self.assert_raw_rejected(b"{}", {"Content-Length": "70000"})

    def test_rejects_invalid_field_values(self):
        cases = {
            "string temperature": {"temperature_c": "EXTREME_HEAT"},
            "NaN temperature": {"temperature_c": float("nan")},
            "infinite temperature": {"temperature_c": float("inf")},
            "boolean temperature": {"temperature_c": True},
            # Design decision: accepted range is -60..100 C.
            "implausible temperature": {"temperature_c": 9999},
            "boolean sequence": {"sequence": True},
            "string sequence": {"sequence": "1"},
            "negative sequence": {"sequence": -1},
            "empty device_id": {"device_id": ""},
            "non-string device_id": {"device_id": 123},
            # Design decision: device_id is at most 64 characters.
            "oversized device_id": {"device_id": "x" * 1000},
            "unparseable timestamp": {"observed_at": "yesterday"},
            "timestamp without timezone": {"observed_at": "2026-10-06T12:00:00"},
        }
        for name, override in cases.items():
            with self.subTest(case=name):
                self.assert_rejected(valid_reading(**override))


class CloudAuthTests(unittest.TestCase):
    def post_with_headers(self, state, headers):
        body = json.dumps(valid_reading()).encode()
        with running_server(make_handler(state)) as cloud:
            return raw_post(cloud, body, {"Content-Length": str(len(body)), **headers})

    def test_missing_key_header_is_rejected_and_counted(self):
        state = CloudState(KEY)
        self.assertEqual(self.post_with_headers(state, {}), 401)
        self.assertEqual(state.rejected, 1)
        self.assertEqual(state.readings, [])

    def test_empty_key_is_rejected(self):
        state = CloudState(KEY)
        self.assertEqual(self.post_with_headers(state, {"X-Legacy-Shared-Key": ""}), 401)

    def test_key_prefix_is_rejected(self):
        state = CloudState(KEY)
        self.assertEqual(self.post_with_headers(state, {"X-Legacy-Shared-Key": KEY[:-1]}), 401)

    def test_auth_is_checked_before_body_parsing(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            status = raw_post(cloud, b"{not json", {"X-Legacy-Shared-Key": "wrong",
                                                    "Content-Length": "9"})
        self.assertEqual(status, 401)

    def test_non_ascii_key_is_rejected_without_crashing(self):
        state = CloudState(KEY)
        self.assertEqual(self.post_with_headers(state, {"X-Legacy-Shared-Key": "ää"}), 401)
        self.assertEqual(state.rejected, 1)

    def test_empty_server_key_does_not_disable_auth(self):
        state = CloudState("")
        self.assertEqual(self.post_with_headers(state, {}), 401)


class CloudSequencingTests(unittest.TestCase):
    def test_increasing_sequences_are_accepted(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            for seq in (1, 2, 3):
                self.assertEqual(post_reading(cloud, valid_reading(sequence=seq)), 202)
        self.assertEqual([r["sequence"] for r in state.readings], [1, 2, 3])

    def test_same_sequence_from_different_devices_is_accepted(self):
        # Guards against a replay check that ignores device_id.
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            self.assertEqual(post_reading(cloud, valid_reading(device_id="a", sequence=1)), 202)
            self.assertEqual(post_reading(cloud, valid_reading(device_id="b", sequence=1)), 202)
        self.assertEqual(len(state.readings), 2)

    def test_rejects_duplicate_sequence(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            self.assertEqual(post_reading(cloud, valid_reading(sequence=42)), 202)
            self.assertEqual(post_reading(cloud, valid_reading(sequence=42)), 409)
        self.assertEqual(len(state.readings), 1)

    def test_rejects_older_sequence_after_newer(self):
        # Design decision: sequence numbers must strictly increase per device.
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            self.assertEqual(post_reading(cloud, valid_reading(sequence=5)), 202)
            self.assertEqual(post_reading(cloud, valid_reading(sequence=3)), 409)


class CloudEndpointTests(unittest.TestCase):
    def test_healthz_and_metrics(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            with urlopen(f"{cloud}/healthz") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(json.load(response), {"status": "ok"})
            with urlopen(f"{cloud}/metrics") as response:
                self.assertEqual(response.status, 200)
                metrics = response.read().decode()
        self.assertIn("cloud_received_readings 0", metrics)
        self.assertIn("cloud_rejected_requests 0", metrics)

    def test_metrics_count_rejected_requests(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            post_reading(cloud, valid_reading(), key="wrong-1")
            post_reading(cloud, valid_reading(), key="wrong-2")
            with urlopen(f"{cloud}/metrics") as response:
                metrics = response.read().decode()
        self.assertIn("cloud_rejected_requests 2", metrics)
        self.assertIn("cloud_received_readings 0", metrics)

    def test_unknown_paths_return_404(self):
        state = CloudState(KEY)
        with running_server(make_handler(state)) as cloud:
            self.assertEqual(raw_post(cloud, b"{}", {"X-Legacy-Shared-Key": KEY,
                "Content-Length": "2"}, path="/v1/other"), 404)
            with self.assertRaises(HTTPError) as error:
                urlopen(f"{cloud}/nope")
            self.assertEqual(error.exception.code, 404)
            error.exception.close()


if __name__ == "__main__":
    unittest.main()
