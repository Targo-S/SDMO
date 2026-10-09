"""Hybrid X25519 + ML-KEM session primitives for the simulation's /v2 protocol.

Only standard primitives from pyca/cryptography are used (ML-KEM, X25519, Ed25519,
HKDF-SHA256, ChaCha20-Poly1305). The message layout is a simulation stand-in for
TLS 1.3 hybrid key exchange and is not intended for production use.
"""

import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 2


@dataclass(frozen=True)
class Suite:
    name: str
    private_cls: type
    public_cls: type
    ek_len: int
    ct_len: int


# ML-KEM-512 is excluded by policy; the backend does not provide it either.
SUITES = {suite.name: suite for suite in (
    Suite("X25519+ML-KEM-768", mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184, 1088),
    Suite("X25519+ML-KEM-1024", mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, 1568, 1568),
)}
DEFAULT_SUITE = "X25519+ML-KEM-768"


class CryptoSelfTestError(RuntimeError):
    pass


class DeviceAuthError(ValueError):
    pass


@dataclass(frozen=True)
class SessionKeys:
    record_key: bytes
    mac_key: bytes


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(value, length=None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("expected a string")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if length is not None and len(raw) != length:
        raise ValueError("unexpected length")
    return raw


def load_hex_secret(path, length=None) -> bytes:
    raw = bytes.fromhex(Path(path).read_text().strip())
    if length is not None and len(raw) != length:
        raise ValueError(f"{path}: expected {length} bytes")
    return raw


def encode_fields(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(part)) + part for part in parts)


def kem_generate(suite: Suite):
    private_key = suite.private_cls.generate()
    return private_key, private_key.public_key().public_bytes_raw()


def kem_encapsulate(suite: Suite, encapsulation_key: bytes):
    if len(encapsulation_key) != suite.ek_len:
        raise ValueError("bad encapsulation key length")
    shared_secret, ciphertext = suite.public_cls.from_public_bytes(encapsulation_key).encapsulate()
    return shared_secret, ciphertext


def kem_decapsulate(suite: Suite, private_key, ciphertext: bytes) -> bytes:
    if len(ciphertext) != suite.ct_len:
        raise ValueError("bad ciphertext length")
    # Implicit rejection: a forged ciphertext yields a pseudorandom secret, not an error.
    return private_key.decapsulate(ciphertext)


def request_mac(secret, gateway_id, suite, ek, x25519_pub, nonce, timestamp) -> bytes:
    data = encode_fields(b"sdmo/v2 init", gateway_id.encode(), suite.encode(), ek, x25519_pub,
                         nonce, struct.pack(">Q", timestamp))
    return hmac.new(secret, data, "sha256").digest()


def transcript_hash(gateway_id, suite, ek, x25519_g, nonce_g, timestamp, ct, x25519_c, nonce_c,
                    session_id) -> bytes:
    data = encode_fields(b"sdmo/v2 transcript", gateway_id.encode(), suite.encode(), ek, x25519_g,
                         nonce_g, struct.pack(">Q", timestamp), ct, x25519_c, nonce_c, session_id)
    return hashlib.sha256(data).digest()


def sign_transcript(identity_key, transcript: bytes) -> bytes:
    return identity_key.sign(b"sdmo/v2 cloud-signature" + transcript)


def verify_transcript(public_key: bytes, transcript: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, b"sdmo/v2 cloud-signature" + transcript)
    except InvalidSignature:
        return False
    return True


def derive_keys(ss_pq: bytes, ss_ec: bytes, nonce_g: bytes, nonce_c: bytes, transcript: bytes) -> SessionKeys:
    def expand(label: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce_g + nonce_c,
                    info=b"sdmo/v2 " + label + transcript).derive(ss_pq + ss_ec)

    return SessionKeys(record_key=expand(b"gateway-to-cloud record"), mac_key=expand(b"cloud-to-gateway mac"))


def confirm_tag(mac_key: bytes, transcript: bytes) -> bytes:
    return hmac.new(mac_key, encode_fields(b"sdmo/v2 confirm", transcript), "sha256").digest()


def ack_tag(mac_key: bytes, session_id: str, counter: int) -> bytes:
    return hmac.new(mac_key, encode_fields(b"sdmo/v2 ack", session_id.encode(), struct.pack(">Q", counter)),
                    "sha256").digest()


def _record_aad(session_id: str, counter: int) -> bytes:
    return encode_fields(b"sdmo/v2 record", session_id.encode(), struct.pack(">Q", counter))


def seal_record(key: bytes, session_id: str, counter: int, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(counter.to_bytes(12, "big"), plaintext, _record_aad(session_id, counter))


def open_record(key: bytes, session_id: str, counter: int, ciphertext: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(counter.to_bytes(12, "big"), ciphertext, _record_aad(session_id, counter))


def device_key(master: bytes, device_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sdmo/device-key " + device_id.encode()).derive(master)


def sign_reading(master: bytes, reading: dict) -> str:
    body = json.dumps(reading, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(device_key(master, reading["device_id"]), body, "sha256").hexdigest()


def verify_reading(master: bytes, reading) -> dict:
    if not isinstance(reading, dict) or not isinstance(reading.get("mac"), str) \
            or not isinstance(reading.get("device_id"), str):
        raise DeviceAuthError("missing device mac")
    body = {key: value for key, value in reading.items() if key != "mac"}
    if not hmac.compare_digest(sign_reading(master, body), reading["mac"]):
        raise DeviceAuthError("invalid device mac")
    return body


def backend_info() -> dict:
    return {"library": "cryptography", "version": metadata.version("cryptography"),
            "suites": ",".join(SUITES)}


def selftest() -> None:
    """Fail closed: pinned key-generation and decapsulation vectors, plus a round trip per suite."""
    vectors = json.loads(Path(__file__).with_name("kat.json").read_text())
    for name, suite in SUITES.items():
        vector = vectors[name]
        private_key = suite.private_cls.from_seed_bytes(bytes.fromhex(vector["seed"]))
        encapsulation_key = private_key.public_key().public_bytes_raw()
        if hashlib.sha256(encapsulation_key).hexdigest() != vector["ek_sha256"]:
            raise CryptoSelfTestError(f"{name}: key generation vector mismatch")
        if private_key.decapsulate(bytes.fromhex(vector["ct"])) != bytes.fromhex(vector["ss"]):
            raise CryptoSelfTestError(f"{name}: decapsulation vector mismatch")
        shared_secret, ciphertext = kem_encapsulate(suite, encapsulation_key)
        if kem_decapsulate(suite, private_key, ciphertext) != shared_secret:
            raise CryptoSelfTestError(f"{name}: round trip mismatch")
