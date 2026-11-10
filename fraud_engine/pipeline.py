"""Records -> windows -> rule hits -> scored alerts. No I/O."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pandas as pd

from fraud_engine.rules import DEFAULT_RULES, FraudRule, evaluate_rules
from fraud_engine.scoring import ScoringConfig, score_hits
from fraud_engine.windows import build_windows
from fraud_engine.anomaly import AnomalyConfig, anomaly_hits


@dataclass(frozen=True)
class DetectionResult:
    alerts: pd.DataFrame
    components: pd.DataFrame


def run_detection(records: pd.DataFrame, rules: Sequence[FraudRule] = DEFAULT_RULES,
                  scoring: ScoringConfig | None = None, network_scope: Sequence[str] = (),
                  anomaly: AnomalyConfig | None = None) -> DetectionResult:
    windows = build_windows(records, network_scope)
    hits = evaluate_rules(windows, tuple(rules))
    if anomaly is not None:
        auxiliary = anomaly_hits(windows.sender, anomaly)
        if anomaly.corroborate_only and not auxiliary.empty:
            keys = ["window_start", "network", "entity_type", "entity_key"]
            existing = hits[keys].drop_duplicates()
            auxiliary = auxiliary.merge(existing, on=keys, how="inner")
        if not auxiliary.empty:
            hits = pd.concat([hits, auxiliary], ignore_index=True)
    alerts, components = score_hits(hits, scoring)
    return DetectionResult(alerts, components)
