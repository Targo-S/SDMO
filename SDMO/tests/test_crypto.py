import unittest
from unittest import mock

from cryptography.exceptions import InvalidTag

from sdmo import crypto

try:
    from kyber_py.ml_kem import ML_KEM_768, ML_KEM_1024
except ImportError:
    ML_KEM_768 = ML_KEM_1024 = None

ORACLES = {"X25519+ML-KEM-768": ML_KEM_768, "X25519+ML-KEM-1024": ML_KEM_1024}


class KemTests(unittest.TestCase):
    def test_round_trip_and_sizes(self):
        for name, suite in crypto.SUITES.items():
            with self.subTest(suite=name):
                private_key, ek = crypto.kem_generate(suite)
                self.assertEqual(len(ek), suite.ek_len)
                secret, ct = crypto.kem_encapsulate(suite, ek)
                self.assertEqual((len(secret), len(ct)), (32, suite.ct_len))
                self.assertEqual(crypto.kem_decapsulate(suite, private_key, ct), secret)

    def test_sizes_match_fips_203(self):
        expected = {"X25519+ML-KEM-768": (1184, 1088), "X25519+ML-KEM-1024": (1568, 1568)}
        for name, sizes in expected.items():
            self.assertEqual((crypto.SUITES[name].ek_len, crypto.SUITES[name].ct_len), sizes)

    def test_default_suite_is_768_and_512_is_not_offered(self):
        self.assertEqual(crypto.DEFAULT_SUITE, "X25519+ML-KEM-768")
        self.assertFalse(any("512" in name for name in crypto.SUITES))

    def test_tampered_ciphertext_is_implicitly_rejected(self):
        for name, suite in crypto.SUITES.items():
            with self.subTest(suite=name):
                private_key, ek = crypto.kem_generate(suite)
                secret, ct = crypto.kem_encapsulate(suite, ek)
                forged = bytes([ct[0] ^ 1]) + ct[1:]
                other = crypto.kem_decapsulate(suite, private_key, forged)
                self.assertEqual(len(other), 32)
                self.assertNotEqual(other, secret)

    def test_wrong_lengths_are_rejected(self):
        suite = crypto.SUITES[crypto.DEFAULT_SUITE]
        private_key, ek = crypto.kem_generate(suite)
        with self.assertRaises(ValueError):
            crypto.kem_encapsulate(suite, ek[:-1])
        with self.assertRaises(ValueError):
            crypto.kem_decapsulate(suite, private_key, b"short")

    def test_known_answer_vectors_pass_and_corruption_is_detected(self):
        crypto.selftest()
        real = crypto.json.loads
        for field in ("ek_sha256", "ss"):
            def corrupted(text, field=field):
                vectors = real(text)
                for vector in vectors.values():
                    vector[field] = "00" * 32
                return vectors
            with self.subTest(field=field), mock.patch.object(crypto.json, "loads", corrupted):
                with self.assertRaises(crypto.CryptoSelfTestError):
                    crypto.selftest()

    @unittest.skipIf(ML_KEM_768 is None, "kyber-py is not installed")
    def test_differential_against_independent_implementation(self):
        seed = bytes(range(64))
        for name, suite in crypto.SUITES.items():
            with self.subTest(suite=name):
                oracle = ORACLES[name]
                oracle_ek, oracle_dk = oracle.key_derive(seed)
                private_key = suite.private_cls.from_seed_bytes(seed)
                self.assertEqual(private_key.public_key().public_bytes_raw(), oracle_ek)
                oracle_secret, oracle_ct = oracle.encaps(oracle_ek)
                self.assertEqual(crypto.kem_decapsulate(suite, private_key, oracle_ct), oracle_secret)
                secret, ct = crypto.kem_encapsulate(suite, oracle_ek)
                self.assertEqual(oracle.decaps(oracle_dk, ct), secret)


class KdfAndRecordTests(unittest.TestCase):
    base = dict(ss_pq=b"p" * 32, ss_ec=b"e" * 32, nonce_g=b"g" * 16, nonce_c=b"c" * 16, transcript=b"t" * 32)

    def test_every_input_changes_the_keys(self):
        reference = crypto.derive_keys(**self.base)
        for field in self.base:
            changed = dict(self.base, **{field: bytes([self.base[field][0] ^ 1]) + self.base[field][1:]})
            with self.subTest(field=field):
                keys = crypto.derive_keys(**changed)
                self.assertNotEqual(keys.record_key, reference.record_key)
                self.assertNotEqual(keys.mac_key, reference.mac_key)

    def test_keys_are_domain_separated(self):
        keys = crypto.derive_keys(**self.base)
        self.assertNotEqual(keys.record_key, keys.mac_key)

    def test_transcript_binds_every_field(self):
        fields = dict(gateway_id="gw", suite="X25519+ML-KEM-768", ek=b"k", x25519_g=b"x", nonce_g=b"n",
                      timestamp=7, ct=b"c", x25519_c=b"y", nonce_c=b"m", session_id=b"s")
        reference = crypto.transcript_hash(**fields)
        for field, value in fields.items():
            changed = dict(fields)
            changed[field] = value + {int: 1, bytes: b"!", str: "!"}[type(value)]
            with self.subTest(field=field):
                self.assertNotEqual(crypto.transcript_hash(**changed), reference)

    def test_field_encoding_is_unambiguous(self):
        self.assertNotEqual(crypto.encode_fields(b"ab", b"c"), crypto.encode_fields(b"a", b"bc"))

    def test_record_tampering_is_detected(self):
        key = b"k" * 32
        sealed = crypto.seal_record(key, "session", 5, b"payload")
        self.assertEqual(crypto.open_record(key, "session", 5, sealed), b"payload")
        for label, args in {
            "ciphertext": (key, "session", 5, bytes([sealed[0] ^ 1]) + sealed[1:]),
            "counter": (key, "session", 6, sealed),
            "session": (key, "other", 5, sealed),
            "key": (b"j" * 32, "session", 5, sealed),
        }.items():
            with self.subTest(changed=label), self.assertRaises(InvalidTag):
                crypto.open_record(*args)

    def test_nonce_differs_per_counter(self):
        key = b"k" * 32
        self.assertNotEqual(crypto.seal_record(key, "s", 1, b"x"), crypto.seal_record(key, "s", 2, b"x"))

    def test_base64_decoding_is_strict(self):
        self.assertEqual(crypto.b64d(crypto.b64e(b"\xfb\xff"), 2), b"\xfb\xff")
        for bad in ("***", "a", "é", 5, None):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                crypto.b64d(bad)
        with self.assertRaises(ValueError):
            crypto.b64d(crypto.b64e(b"abc"), 4)

    def test_acks_are_bound_to_session_and_counter(self):
        tag = crypto.ack_tag(b"m" * 32, "s", 1)
        self.assertNotEqual(tag, crypto.ack_tag(b"m" * 32, "s", 2))
        self.assertNotEqual(tag, crypto.ack_tag(b"m" * 32, "t", 1))


class DeviceFrameTests(unittest.TestCase):
    reading = {"device_id": "dev-1", "sequence": 3, "temperature_c": 21.5, "observed_at": "now"}

    def test_valid_frame_round_trips(self):
        master = b"m" * 32
        frame = dict(self.reading, mac=crypto.sign_reading(master, self.reading))
        self.assertEqual(crypto.verify_reading(master, frame), self.reading)

    def test_tampering_and_wrong_keys_are_rejected(self):
        master = b"m" * 32
        mac = crypto.sign_reading(master, self.reading)
        cases = {
            "value": dict(self.reading, temperature_c=99.0, mac=mac),
            "device": dict(self.reading, device_id="dev-2", mac=mac),
            "missing": dict(self.reading),
            "key": dict(self.reading, mac=crypto.sign_reading(b"n" * 32, self.reading)),
        }
        for label, frame in cases.items():
            with self.subTest(case=label), self.assertRaises(crypto.DeviceAuthError):
                crypto.verify_reading(master, frame)

    def test_per_device_keys_differ(self):
        self.assertNotEqual(crypto.device_key(b"m" * 32, "a"), crypto.device_key(b"m" * 32, "b"))


if __name__ == "__main__":
    unittest.main()
