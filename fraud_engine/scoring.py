"""Explainable risk score: S = 100 * (1 - prod_i(1 - w_i * s_i)).

More evidence raises the score, it never exceeds 100, and every component is
stored so an alert can be traced to the rule versions that produced it.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

ALERT_KEYS = ["window_start", "entity_type", "entity_key", "network"]
BAND_NAMES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class ScoringConfig:
    band_lower_bounds: tuple[float, float, float] = (25.0, 50.0, 75.0)  # medium, high, critical


def combine(contributions: list[float]) -> float:
    prod = 1.0
    for c in contributions:
        prod *= 1.0 - c
    return 100.0 * (1.0 - prod)


def band_for(score: np.ndarray | pd.Series, cfg: ScoringConfig) -> np.ndarray:
    s = np.asarray(score, dtype=float)
    m, h, c = cfg.band_lower_bounds
    return np.select([s >= c, s >= h, s >= m], ["critical", "high", "medium"], default="low")


def score_hits(hits: pd.DataFrame, cfg: ScoringConfig | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (alerts, components). One alert per entity+window+network."""
    cfg = cfg or ScoringConfig()
    alert_cols = [*ALERT_KEYS, "risk_score", "band"]
    if hits.empty:
        return pd.DataFrame(columns=alert_cols), pd.DataFrame(columns=[*ALERT_KEYS, "rule_key", "rule_version",
                                                                      "severity", "contribution", "evidence"])
    comp = hits.copy()
    comp["contribution"] = comp["weight"].astype(float) * comp["severity"].astype(float)
    remainder = (1.0 - comp["contribution"]).groupby([comp[k] for k in ALERT_KEYS], sort=True).prod()
    alerts = (100.0 * (1.0 - remainder)).rename("risk_score").reset_index()
    alerts["risk_score"] = alerts["risk_score"].round(2)
    alerts["band"] = band_for(alerts["risk_score"], cfg)
    components = comp[[*ALERT_KEYS, "rule_key", "rule_version", "severity", "contribution", "evidence"]]
    return alerts.sort_values("risk_score", ascending=False, ignore_index=True), components.reset_index(drop=True)
