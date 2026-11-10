"""Access-token verification (PyJWT). RS256 only.

Phase 2 trusts a locally configured public key; Phase 3 swaps the resolver for Keycloak's JWKS
without touching routes or the permission map. The signature, issuer, audience and expiry are all
required. Claims -> Principal: roles come from `realm_access.roles` (Keycloak layout); unknown roles
are ignored.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import jwt

from backend.auth.permissions import ROLES, Principal

ALGORITHMS = ["RS256"]  # never HS*, never "none": blocks algorithm-confusion attacks
KeyResolver = Callable[[str], Any]  # token -> public key (Phase 3: look up by `kid`)


class AuthError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def verify_token(token: str, resolve_key: KeyResolver, issuer: str, audience: str,
                 leeway_seconds: int = 0) -> Principal:
    try:
        claims = jwt.decode(
            token, resolve_key(token), algorithms=ALGORITHMS, audience=audience, issuer=issuer,
            leeway=leeway_seconds, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise AuthError("invalid_audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError("invalid_issuer") from exc
    except jwt.InvalidSignatureError as exc:
        raise AuthError("invalid_signature") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise AuthError("missing_claim") from exc
    except jwt.PyJWTError as exc:
        raise AuthError("malformed") from exc
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise AuthError("missing_claim")
    realm_access = claims.get("realm_access", {})
    if not isinstance(realm_access, dict):
        raise AuthError("malformed")
    raw_roles = realm_access.get("roles", [])
    if not isinstance(raw_roles, list):
        raise AuthError("malformed")
    roles = frozenset(r for r in raw_roles if isinstance(r, str) and r in ROLES)
    username = str(claims.get("preferred_username") or sub)[:200]
    return Principal(sub=sub, username=username, roles=roles)
