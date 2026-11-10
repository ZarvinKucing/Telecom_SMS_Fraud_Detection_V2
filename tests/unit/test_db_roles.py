from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from backend.db_roles import RuntimeRoleError, verify_runtime_role


class RuntimeRoleTests(unittest.TestCase):
    def _engine(self, row: dict[str, bool]) -> MagicMock:
        result = MagicMock()
        result.mappings.return_value.one.return_value = row
        connection = MagicMock()
        connection.execute.return_value = result
        engine = MagicMock()
        engine.connect.return_value.__enter__.return_value = connection
        return engine

    def test_accepts_a_runtime_role_with_only_expected_privileges(self):
        fields = (
            "rolsuper rolcreatedb rolcreaterole rolreplication rolbypassrls db_create db_temp "
            "schema_create owns_public_object owner_or_privileged_role_member audit_update "
            "audit_delete audit_truncate"
        ).split()
        verify_runtime_role(self._engine(dict.fromkeys(fields, False)))

    def test_rejects_transitive_membership_in_a_privileged_role(self):
        fields = (
            "rolsuper rolcreatedb rolcreaterole rolreplication rolbypassrls db_create db_temp "
            "schema_create owns_public_object owner_or_privileged_role_member audit_update "
            "audit_delete audit_truncate"
        ).split()
        row = dict.fromkeys(fields, False)
        row["owner_or_privileged_role_member"] = True
        with self.assertRaises(RuntimeRoleError):
            verify_runtime_role(self._engine(row))


if __name__ == "__main__":
    unittest.main()
