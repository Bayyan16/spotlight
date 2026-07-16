"""Public-key endpoint helper.

The FastAPI layer imports :func:`public_key_response` and wires it under
``/api/non_repudiation/public_key`` so third-party auditors can pull the
workspace's Ed25519 public key + fingerprint and verify any signed entry
they find in a finding's chain_of_custody.

We do NOT edit ``spotlight/api/app.py`` from this module — the integration
pass wires the route.
"""
from __future__ import annotations

from .signing import Signer


def public_key_response() -> dict:
    """Return the workspace public key in a JSON-serializable envelope.

    Shape::

        {
            "algorithm": "Ed25519",
            "public_key_b64": "<base64 raw 32-byte public key>",
            "fingerprint": "<sha256(raw)[:16]>",
        }
    """
    s = Signer()
    return {
        "algorithm": "Ed25519",
        "public_key_b64": s.public_key_b64(),
        "fingerprint": s.fingerprint,
    }
