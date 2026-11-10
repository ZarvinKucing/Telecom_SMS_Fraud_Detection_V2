"""Isolation Forest anomaly signal over per-sender hourly windows.

SECONDARY signal only. There are no fraud labels in real data, so the model cannot be validated
there; it is evaluated on the synthetic generator only (see evaluate_anomaly). It is fitted on the
batch it scores (transductive), so it needs enough windows to describe "normal".
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from fraud_engine.rules import HIT_COLUMNS, RuleRecord

RULE_KEY = "anomaly_isolation_forest"


@dataclass(frozen=True)
class AnomalyConfig:
    n_estimators: int = 200
    percentile_threshold: float = 0.995  # flag windows at or above this anomaly percentile
    min_windows: int = 200               # below this, the model is skipped
    weight: float = 0.3
    version: int = 1
    seed: int = 0
    corroborate_only: bool = True        # only raise scores of entities that rules already flagged


def as_rule_record(cfg: AnomalyConfig) -> RuleRecord:
    return RuleRecord(RULE_KEY, "anomaly_model", {"percentile_threshold": cfg.percentile_threshold,
                                                  "n_estimators": cfg.n_estimators}, cfg.weight, cfg.version)


def build_features(sender_windows: pd.DataFrame) -> pd.DataFrame:
    w = sender_windows
    hour = w["window_start"].dt.hour.to_numpy()
    count = w["msg_count"].to_numpy(dtype=float)
    distinct = w["distinct_destinations"].to_numpy(dtype=float)
    return pd.DataFrame({
        "log_volume": np.log1p(count),
        "log_distinct_destinations": np.log1p(distinct),
        "repeat_ratio": 1.0 - distinct / np.maximum(count, 1.0),
        "delivery_ratio": w["delivery_ratio"].to_numpy(dtype=float),
        "hour_sin": np.sin(2 * np.pi * hour / 24),
        "hour_cos": np.cos(2 * np.pi * hour / 24),
    }, index=w.index)


def score_windows(sender_windows: pd.DataFrame, cfg: AnomalyConfig | None = None) -> pd.Series:
    """Anomaly percentile in (0, 1] per row; 1.0 is the most anomalous."""
    cfg = cfg or AnomalyConfig()
    model = IsolationForest(n_estimators=cfg.n_estimators, random_state=cfg.seed)
    features = build_features(sender_windows)
    model.fit(features)
    raw = -model.score_samples(features)
    return pd.Series(raw, index=sender_windows.index).rank(pct=True)


def anomaly_hits(sender_windows: pd.DataFrame, cfg: AnomalyConfig | None = None) -> pd.DataFrame:
    cfg = cfg or AnomalyConfig()
    if len(sender_windows) < cfg.min_windows:
        return pd.DataFrame(columns=HIT_COLUMNS)
    pct = score_windows(sender_windows, cfg)
    flagged = sender_windows[pct >= cfg.percentile_threshold]
    if flagged.empty:
        return pd.DataFrame(columns=HIT_COLUMNS)
    p = pct[flagged.index]
    evidence = [{"model": "isolation_forest", "percentile": round(float(q), 4), "msg_count": int(c),
                 "distinct_destinations": int(d), "delivery_ratio": round(float(r), 3)}
                for q, c, d, r in zip(p, flagged["msg_count"], flagged["distinct_destinations"],
                                      flagged["delivery_ratio"], strict=True)]
    return pd.DataFrame({
        "rule_key": RULE_KEY, "rule_version": cfg.version, "weight": cfg.weight,
        "window_start": flagged["window_start"].to_numpy(), "network": flagged["network"].to_numpy(),
        "entity_type": "sender", "entity_key": flagged["source_addr"].to_numpy(),
        "observed": p.to_numpy(dtype=float), "threshold": cfg.percentile_threshold,
        "severity": p.to_numpy(dtype=float), "evidence": evidence,
    }, columns=HIT_COLUMNS)
