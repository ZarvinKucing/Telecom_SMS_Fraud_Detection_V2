import time
import unittest

import jwt

from backend.auth.permissions import PERMISSIONS, Principal, permissions_for
from backend.auth.testing import AUDIENCE, ISSUER, TestKeyPair, make_token
from backend.auth.tokens import AuthError, verify_token

KEYS = TestKeyPair.generate()
OTHER = TestKeyPair.generate()


def verify(token):
    return verify_token(token, lambda _t: KEYS.public_pem, ISSUER, AUDIENCE)


class PermissionMatrixTests(unittest.TestCase):
    # Written out literally (from the blueprint's matrix) so a code change cannot silently widen access.
    EXPECTED = {
        "administrator": {"fraud:summary:read", "fraud:rules:read", "security:alert:read", "audit:read",
                          "iam:users:manage", "iam:roles:assign", "config:write"},
        "fraud_analyst": {"fraud:summary:read", "fraud:alert:read", "fraud:msisdn:unmask", "fraud:case:read",
                          "fraud:case:write", "fraud:rules:read", "fraud:rules:write", "sms:ingest"},
        "security_analyst": {"security:alert:read", "security:incident:write", "audit:read"},
        "viewer": {"fraud:summary:read"},
    }

    def test_matrix_matches_blueprint(self):
        self.assertEqual({r: set(p) for r, p in PERMISSIONS.items()}, self.EXPECTED)

    def test_admin_is_not_a_superuser(self):
        admin = PERMISSIONS["administrator"]
        for p in ("fraud:alert:read", "fraud:msisdn:unmask", "fraud:case:write", "fraud:rules:write", "sms:ingest"):
            self.assertNotIn(p, admin)

    def test_viewer_has_no_identifier_access(self):
        self.assertEqual(PERMISSIONS["viewer"], {"fraud:summary:read"})

    def test_roles_union_and_unknown_roles_grant_nothing(self):
        both = permissions_for({"viewer", "security_analyst"})
        self.assertEqual(both, self.EXPECTED["viewer"] | self.EXPECTED["security_analyst"])
        self.assertEqual(permissions_for({"superuser", "root"}), frozenset())
        self.assertFalse(Principal("s", "u", frozenset()).can("fraud:summary:read"))


class TokenTests(unittest.TestCase):
    def test_valid_token_yields_principal_with_known_roles_only(self):
        p = verify(make_token(KEYS.private_pem, "abc", ["fraud_analyst", "hacker"], username="alice"))
        self.assertEqual((p.sub, p.username, p.roles), ("abc", "alice", frozenset({"fraud_analyst"})))

    def _code(self, token, **kw):
        with self.assertRaises(AuthError) as cm:
            verify_token(token, lambda _t: KEYS.public_pem, kw.get("issuer", ISSUER), kw.get("audience", AUDIENCE))
        return cm.exception.code

    def test_expired(self):
        self.assertEqual(self._code(make_token(KEYS.private_pem, "a", [], expires_in=-10)), "expired")

    def test_wrong_signing_key(self):
        self.assertEqual(self._code(make_token(OTHER.private_pem, "a", ["viewer"])), "invalid_signature")

    def test_wrong_audience_and_issuer(self):
        self.assertEqual(self._code(make_token(KEYS.private_pem, "a", [], audience="other-api")), "invalid_audience")
        self.assertEqual(self._code(make_token(KEYS.private_pem, "a", [], issuer="https://evil/")), "invalid_issuer")

    def test_algorithm_confusion_hs256_with_public_key_is_rejected(self):
        # Hand-built forgery: the library refuses to sign this, an attacker would not use the library.
        import base64
        import hashlib
        import hmac
        import json

        def b64(raw):
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        now = int(time.time())
        head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64(json.dumps({"sub": "a", "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 99,
                               "realm_access": {"roles": ["administrator"]}}).encode())
        sig = b64(hmac.new(KEYS.public_pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
        self.assertIn(self._code(f"{head}.{body}.{sig}"), {"malformed", "invalid_signature"})

    def test_alg_none_is_rejected(self):
        now = int(time.time())
        unsigned = jwt.encode({"sub": "a", "iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 99},
                              None, algorithm="none")
        self.assertEqual(self._code(unsigned), "malformed")

    def test_missing_required_claims(self):
        now = int(time.time())
        no_exp = jwt.encode({"sub": "a", "iss": ISSUER, "aud": AUDIENCE, "iat": now}, KEYS.private_pem,
                            algorithm="RS256")
        self.assertEqual(self._code(no_exp), "missing_claim")

    def test_garbage_and_tampered(self):
        self.assertEqual(self._code("not-a-jwt"), "malformed")
        good = make_token(KEYS.private_pem, "a", ["viewer"])
        head, payload, sig = good.split(".")
        self.assertIn(self._code(f"{head}.{payload[:-2]}xx.{sig}"), {"malformed", "invalid_signature"})

    def test_malformed_roles_claim(self):
        tok = make_token(KEYS.private_pem, "a", [], extra={"realm_access": {"roles": "administrator"}})
        self.assertEqual(self._code(tok), "malformed")

    def test_malformed_realm_access_claim(self):
        tok = make_token(KEYS.private_pem, "a", [], extra={"realm_access": "administrator"})
        self.assertEqual(self._code(tok), "malformed")


if __name__ == "__main__":
    unittest.main()
