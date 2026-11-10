"""Helpers to mint tokens with a locally generated key pair (tests and local demos only).

No key material is stored in the repository: a fresh RSA key is generated at runtime.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://issuer.test/realms/fraud"
AUDIENCE = "fraud-api"


@dataclass(frozen=True)
class TestKeyPair:
    __test__ = False  # not a pytest class
    private_pem: bytes
    public_pem: bytes

    @classmethod
    def generate(cls) -> TestKeyPair:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo))


def make_token(private_pem: bytes, sub: str, roles: list[str], *, issuer: str = ISSUER,
               audience: str = AUDIENCE, expires_in: int = 300, username: str | None = None,
               extra: dict[str, Any] | None = None, algorithm: str = "RS256") -> str:
    now = int(time.time())
    claims: dict[str, Any] = {"sub": sub, "preferred_username": username or sub, "iss": issuer,
                              "aud": audience, "iat": now, "exp": now + expires_in,
                              "realm_access": {"roles": roles}}
    claims.update(extra or {})
    return jwt.encode(claims, private_pem, algorithm=algorithm)
