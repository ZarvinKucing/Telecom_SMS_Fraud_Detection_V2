"""Records -> windows -> rule hits -> scored alerts. No I/O."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pandas as pd

from fraud_engine.rules import DEFAULT_RULES, FraudRule, evaluate_rules
from fraud_engine.scoring import ScoringConfig, score_hits
from fraud_engine.windows import build_windows


@dataclass(frozen=True)
class DetectionResult:
    alerts: pd.DataFrame
    components: pd.DataFrame


def run_detection(records: pd.DataFrame, rules: Sequence[FraudRule] = DEFAULT_RULES,
                  scoring: ScoringConfig | None = None, network_scope: Sequence[str] = ()) -> DetectionResult:
    hits = evaluate_rules(build_windows(records, network_scope), tuple(rules))
    alerts, components = score_hits(hits, scoring)
    return DetectionResult(alerts, components)
