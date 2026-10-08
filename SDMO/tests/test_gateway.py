"""Gateway: forwarding behaviour, error handling and its own endpoints."""
import json
import threading
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from sdmo.cloud import CloudState, make_handler as make_cloud_handler
from sdmo.gateway import make_handler, poll_once
from tests.helpers import (KEY, running_server, setUpModule, stub_handler,  # noqa: F401
                           tearDownModule, unused_port, valid_reading)


class GatewayForwardingTests(unittest.TestCase):
    def test_sends_key_and_unmodified_reading(self):
        reading = valid_reading(sequence=7)
        received = []
        with running_server(stub_handler(200, json.dumps(reading).encode())) as device, \
             running_server(stub_handler(202, received=received)) as cloud:
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["headers"].get("X-Legacy-Shared-Key"), KEY)
        self.assertEqual(received[0]["headers"].get("Content-Type"), "application/json")
        self.assertEqual(json.loads(received[0]["body"]), reading)

    def test_cloud_redirect_does_not_forward_key(self):
        # A redirecting cloud URL must not cause the shared key to be sent elsewhere.
        reading = json.dumps(valid_reading()).encode()
        elsewhere = []
        with running_server(stub_handler(200, received=elsewhere)) as other_host, \
             running_server(stub_handler(200, reading)) as device, \
             running_server(stub_handler(302, headers={"Location": f"{other_host}/collect"})) as cloud, \
             self.assertRaises(URLError):
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        leaked = [r for r in elsewhere if r["headers"].get("X-Legacy-Shared-Key")]
        self.assertEqual(leaked, [])


class GatewayErrorTests(unittest.TestCase):
    def test_device_unreachable_raises_and_forwards_nothing(self):
        state = CloudState(KEY)
        with running_server(make_cloud_handler(state)) as cloud, self.assertRaises(URLError):
            poll_once(f"http://127.0.0.1:{unused_port()}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertEqual(state.readings, [])

    def test_device_error_status_raises(self):
        state = CloudState(KEY)
        with running_server(stub_handler(500)) as device, \
             running_server(make_cloud_handler(state)) as cloud, \
             self.assertRaises(HTTPError) as error:
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertEqual(error.exception.code, 500)
        error.exception.close()
        self.assertEqual(state.readings, [])

    def test_device_invalid_json_raises(self):
        state = CloudState(KEY)
        with running_server(stub_handler(200, b"<html>oops</html>")) as device, \
             running_server(make_cloud_handler(state)) as cloud, \
             self.assertRaises(ValueError):
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertEqual(state.readings, [])

    def test_invalid_device_reading_is_rejected_by_cloud(self):
        state = CloudState(KEY)
        with running_server(stub_handler(200, b'{"device_id": "x"}')) as device, \
             running_server(make_cloud_handler(state)) as cloud, \
             self.assertRaises(HTTPError) as error:
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
        self.assertEqual(state.readings, [])

    def test_cloud_error_statuses_raise(self):
        reading = json.dumps(valid_reading()).encode()
        for status in (401, 500, 503):
            with self.subTest(status=status), \
                 running_server(stub_handler(200, reading)) as device, \
                 running_server(stub_handler(status)) as cloud, \
                 self.assertRaises(HTTPError) as error:
                poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
            self.assertEqual(error.exception.code, status)
            error.exception.close()

    def test_cloud_200_instead_of_202_is_treated_as_failure(self):
        reading = json.dumps(valid_reading()).encode()
        with running_server(stub_handler(200, reading)) as device, \
             running_server(stub_handler(200)) as cloud, \
             self.assertRaises(URLError) as error:
            poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", KEY)
        self.assertNotIsInstance(error.exception, HTTPError)


class GatewayEndpointTests(unittest.TestCase):
    def test_healthz_and_metrics(self):
        metrics = {"forwarded_total": 3, "errors_total": 1}
        with running_server(make_handler(metrics, threading.Lock())) as gateway:
            with urlopen(f"{gateway}/healthz") as response:
                self.assertEqual(json.load(response), {"status": "ok"})
            with urlopen(f"{gateway}/metrics") as response:
                body = response.read().decode()
        self.assertIn("gateway_forwarded_total 3", body)
        self.assertIn("gateway_errors_total 1", body)


if __name__ == "__main__":
    unittest.main()
