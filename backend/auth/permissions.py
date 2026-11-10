"""Declarative role -> permission map. Keycloak issues the four coarse roles; this map is the policy.

Administrator is an identity/configuration role, not a super-user: it cannot read alert detail,
unmask numbers, or work cases. A person with two duties holds two roles.
Deviation from the blueprint matrix: `fraud:case:read` is added (fraud analyst only) because the
blueprint's own flow reads cases but its matrix lists only `fraud:case:write`.
"""
from __future__ import annotations

from dataclasses import dataclass

ADMIN, FRAUD, SECURITY, VIEWER = "administrator", "fraud_analyst", "security_analyst", "viewer"
ROLES = (ADMIN, FRAUD, SECURITY, VIEWER)

PERMISSIONS: dict[str, frozenset[str]] = {
    ADMIN: frozenset({"fraud:summary:read", "fraud:rules:read", "security:alert:read", "audit:read",
                      "iam:users:manage", "iam:roles:assign", "config:write"}),
    FRAUD: frozenset({"fraud:summary:read", "fraud:alert:read", "fraud:msisdn:unmask", "fraud:case:read",
                      "fraud:case:write", "fraud:rules:read", "fraud:rules:write", "sms:ingest"}),
    SECURITY: frozenset({"security:alert:read", "security:incident:write", "audit:read"}),
    VIEWER: frozenset({"fraud:summary:read"}),
}


def permissions_for(roles: frozenset[str] | set[str]) -> frozenset[str]:
    out: set[str] = set()
    for role in roles:
        out |= PERMISSIONS.get(role, frozenset())
    return frozenset(out)


@dataclass(frozen=True)
class Principal:
    sub: str
    username: str
    roles: frozenset[str]

    @property
    def permissions(self) -> frozenset[str]:
        return permissions_for(self.roles)

    def can(self, permission: str) -> bool:
        return permission in self.permissions
