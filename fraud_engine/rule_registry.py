"""Seed and load versioned rules through any repo exposing list_rules/add_rule_version."""
from __future__ import annotations

from typing import Any

from fraud_engine.rules import DEFAULT_RULES, FraudRule


def seed_default_rules(repo: Any) -> int:
    # SQLRepo serializes the existence check and inserts with one advisory transaction lock.
    # MemoryRepo uses its re-entrant transaction lock; other Repo implementations can follow suit.
    seed = getattr(repo, "seed_default_rules", None)
    if callable(seed):
        return seed(DEFAULT_RULES)
    with repo.transaction():
        existing = {r["rule_key"] for r in repo.list_rules()}
        added = 0
        for rule in DEFAULT_RULES:
            if rule.rule_key in existing:
                continue
            repo.add_rule_version(rule.rule_key, rule.rule_type, dict(rule.params), rule.weight, rule.enabled)
            existing.add(rule.rule_key)
            added += 1
        return added


def load_rules(repo: Any) -> list[FraudRule]:
    return [FraudRule(rule_key=r["rule_key"], rule_type=r["rule_type"], params=r["params"],
                      weight=float(r["weight"]), version=r["version"], enabled=r["enabled"])
            for r in repo.list_rules()]
