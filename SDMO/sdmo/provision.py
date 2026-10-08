"""Create the simulation's keys and secrets: python -m sdmo.provision DIR [GATEWAY_ID ...]

Existing files are never overwritten, so re-running is safe.
"""

import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def _write_secret(path: Path, text: str) -> bool:
    if path.exists():
        return False
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stored:
        stored.write(text)
    return True


def provision(directory, gateway_ids=("gateway-01",)):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    identity = Ed25519PrivateKey.generate()
    seed = identity.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    if _write_secret(directory / "cloud_identity.key", seed.hex()):
        _write_secret(directory / "cloud_identity.pub", identity.public_key().public_bytes_raw().hex())
    _write_secret(directory / "device_master.secret", os.urandom(32).hex())

    registry_path = directory / "registry.json"
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    for gateway_id in gateway_ids:
        secret_path = directory / f"{gateway_id}.secret"
        if not secret_path.exists():
            _write_secret(secret_path, os.urandom(32).hex())
        registry[gateway_id] = secret_path.read_text().strip()
    registry_path.write_text(json.dumps(registry))
    os.chmod(registry_path, 0o600)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m sdmo.provision DIR [GATEWAY_ID ...]")
    provision(sys.argv[1], tuple(sys.argv[2:]) or ("gateway-01",))
    print(f"provisioned {sys.argv[1]}")
