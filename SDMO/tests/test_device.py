"""Simulated legacy device."""
import json
import unittest
from datetime import datetime
from urllib.request import urlopen

from sdmo.legacy_device import make_handler
from tests.helpers import running_server, setUpModule, tearDownModule  # noqa: F401


class LegacyDeviceTests(unittest.TestCase):
    def test_readings_are_well_formed_and_sequential(self):
        with running_server(make_handler()) as device:
            readings = []
            for _ in range(3):
                with urlopen(f"{device}/v1/reading") as response:
                    readings.append(json.load(response))
        self.assertEqual([r["sequence"] for r in readings], [1, 2, 3])
        for reading in readings:
            self.assertEqual(set(reading), {"device_id", "sequence", "temperature_c", "observed_at"})
            self.assertIsInstance(reading["temperature_c"], float)
            self.assertTrue(-60 <= reading["temperature_c"] <= 100)
            self.assertIsNotNone(datetime.fromisoformat(reading["observed_at"]).tzinfo)

    def test_healthz(self):
        with running_server(make_handler()) as device, \
             urlopen(f"{device}/healthz") as response:
            self.assertEqual(json.load(response), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
