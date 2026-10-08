"""System-level test: builds and starts the real stack with Docker Compose and
checks that readings flow from the legacy device through the gateway to the
cloud. Skipped unless SDMO_SYSTEM_TESTS=1, so normal test runs need no Docker."""
import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

PROJECT_DIR = Path(__file__).resolve().parents[2]  # folder containing compose.yaml
CLOUD = "http://localhost:8081"
GATEWAY = "http://localhost:8080"
DEVICE_ID = "legacy-sensor-01"
MIN_READINGS = 3
TIMEOUT_SECONDS = 30


def compose(*args, check=True):
    return subprocess.run(["docker", "compose", *args], cwd=PROJECT_DIR, check=check)


def get_json(url):
    with urlopen(url, timeout=5) as response:
        return json.load(response)


def get_text(url):
    with urlopen(url, timeout=5) as response:
        return response.read().decode()


def wait_for_readings(minimum, timeout):
    """Poll the cloud until `minimum` readings have arrived or `timeout` passes.
    Returns whatever readings exist at that point."""
    deadline = time.monotonic() + timeout
    readings = []
    while time.monotonic() < deadline:
        readings = get_json(f"{CLOUD}/v1/readings")["readings"]
        if len(readings) >= minimum:
            break
        time.sleep(1)
    return readings


@unittest.skipUnless(os.environ.get("SDMO_SYSTEM_TESTS") == "1",
                     "set SDMO_SYSTEM_TESTS=1 to run the Docker Compose system test")
class StackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compose("down", check=False)  # start from a clean stack: empty cloud, device at sequence 1
        try:
            compose("up", "-d", "--build", "--wait")
            cls.readings = wait_for_readings(MIN_READINGS, TIMEOUT_SECONDS)
        except BaseException:
            compose("down", check=False)  # tearDownClass does not run if setUpClass fails
            raise

    @classmethod
    def tearDownClass(cls):
        compose("down", check=False)

    def test_services_report_healthy(self):
        for name, url in (("cloud", CLOUD), ("gateway", GATEWAY)):
            with self.subTest(service=name):
                self.assertEqual(get_json(f"{url}/healthz"), {"status": "ok"})

    def test_readings_reach_the_cloud(self):
        self.assertGreaterEqual(len(self.readings), MIN_READINGS)

    def test_readings_come_from_the_device_in_sequence(self):
        self.assertTrue(self.readings, "no readings arrived")
        self.assertEqual({r["device_id"] for r in self.readings}, {DEVICE_ID})
        sequences = [r["sequence"] for r in self.readings]
        self.assertEqual(sequences, list(range(1, len(sequences) + 1)))

    def test_no_rejected_requests_or_forwarding_errors(self):
        self.assertIn("cloud_rejected_requests 0", get_text(f"{CLOUD}/metrics"))
        self.assertIn("gateway_errors_total 0", get_text(f"{GATEWAY}/metrics"))


if __name__ == "__main__":
    unittest.main()
