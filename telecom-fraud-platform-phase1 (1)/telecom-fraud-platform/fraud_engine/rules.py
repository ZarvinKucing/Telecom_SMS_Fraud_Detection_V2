"""Configurable fraud rules evaluated over hourly windows (vectorized).

Thresholds shipped here are illustrative defaults, not production values.
Rules are plain data (see FraudRule) so they can later live in the fraud_rules table.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from fraud_engine.windows import Windows

HIT_COLUMNS = ["rule_key", "rule_version", "weight", "window_start", "network", "entity_type",
               "entity_key", "observed", "threshold", "severity", "evidence"]

_REQUIRED_PARAMS: dict[str, tuple[str, ...]] = {
    "repeated_destination": ("threshold",),
    "repeated_destination_per_sender": ("threshold",),
    "spiking_sender": ("ratio", "min_volume", "lookback_days", "min_history_days", "baseline_floor"),
}


@dataclass(frozen=True)
class FraudRule:
    rule_key: str
    rule_type: str
    params: dict[str, Any]
    weight: float
    version: int = 1
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.rule_type not in _REQUIRED_PARAMS:
            raise ValueError(f"unknown rule_type: {self.rule_type}")
        missing = [p for p in _REQUIRED_PARAMS[self.rule_type] if p not in self.params]
        if missing:
            raise ValueError(f"rule {self.rule_key}: missing params {missing}")
        if any(not isinstance(v, int | float) or v <= 0 for v in self.params.values()):
            raise ValueError(f"rule {self.rule_key}: params must be positive numbers")
        if not 0 < self.weight <= 1:
            raise ValueError(f"rule {self.rule_key}: weight must be in (0, 1]")


DEFAULT_RULES: tuple[FraudRule, ...] = (
    FraudRule("repeated_destination", "repeated_destination", {"threshold": 25}, weight=0.6),
    FraudRule("repeated_destination_per_sender", "repeated_destination_per_sender",
              {"threshold": 25}, weight=0.3),
    FraudRule("spiking_sender", "spiking_sender",
              {"ratio": 5.0, "min_volume": 40, "lookback_days": 7, "min_history_days": 3,
               "baseline_floor": 5.0}, weight=0.5),
)


def load_rules(path: str | Path) -> list[FraudRule]:
    data = json.loads(Path(path).read_text())
    return [FraudRule(**item) for item in data]


def severity(observed: np.ndarray | pd.Series, threshold: float) -> np.ndarray:
    """0.5 just past the threshold, rising linearly to 1.0 at twice the threshold."""
    obs = np.asarray(observed, dtype=float)
    return np.clip(0.5 + 0.5 * (obs - threshold) / threshold, 0.0, 1.0)


def _frame(rule: FraudRule, base: pd.DataFrame, entity_type: str, entity_key: pd.Series,
           observed: pd.Series, threshold: float, evidence: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame({
        "rule_key": rule.rule_key, "rule_version": rule.version, "weight": rule.weight,
        "window_start": base["window_start"].to_numpy(), "network": base["network"].to_numpy(),
        "entity_type": entity_type, "entity_key": entity_key.to_numpy(),
        "observed": observed.to_numpy(dtype=float), "threshold": threshold,
        "severity": severity(observed, threshold), "evidence": evidence,
    }, columns=HIT_COLUMNS)


def _repeated_destination(win: Windows, rule: FraudRule) -> pd.DataFrame:
    thr = float(rule.params["threshold"])
    hit = win.destination[win.destination["msg_count"] > thr]
    ev = [{"msg_count": int(c), "distinct_senders": int(s)}
          for c, s in zip(hit["msg_count"], hit["distinct_senders"], strict=True)]
    return _frame(rule, hit, "destination", hit["destination_addr"], hit["msg_count"], thr, ev)


def _repeated_destination_per_sender(win: Windows, rule: FraudRule) -> pd.DataFrame:
    thr = float(rule.params["threshold"])
    hit = win.sender_destination[win.sender_destination["msg_count"] > thr]
    key = hit["source_addr"] + ">" + hit["destination_addr"]
    ev = [{"msg_count": int(c)} for c in hit["msg_count"]]
    return _frame(rule, hit, "sender_destination", key, hit["msg_count"], thr, ev)


def _spiking_sender(win: Windows, rule: FraudRule) -> pd.DataFrame:
    p = rule.params
    sh = win.sender
    empty = pd.DataFrame(columns=HIT_COLUMNS)
    if sh.empty:
        return empty
    ratio, floor = float(p["ratio"]), float(p["baseline_floor"])
    lookback, min_hist = int(p["lookback_days"]), int(p["min_history_days"])
    cand = sh[sh["msg_count"] >= p["min_volume"]]
    if cand.empty:
        return empty
    keys = ["network", "source_addr"]
    first_seen = sh.groupby(keys)["window_start"].min().rename("first_seen")
    cand = cand.join(first_seen, on=keys)
    counts = sh.set_index([*keys, "window_start"])["msg_count"]
    day = pd.Timedelta(days=1)
    lagged = np.full((len(cand), lookback), np.nan)
    for lag in range(1, lookback + 1):
        shifted = cand["window_start"] - lag * day
        valid = (shifted >= cand["first_seen"]).to_numpy()
        idx = pd.MultiIndex.from_arrays([cand["network"], cand["source_addr"], shifted])
        vals = counts.reindex(idx).fillna(0.0).to_numpy()  # absent hour == zero messages
        lagged[:, lag - 1] = np.where(valid, vals, np.nan)
    n_valid = (~np.isnan(lagged)).sum(axis=1)
    keep = n_valid >= min_hist
    if not keep.any():
        return empty
    cand, lagged = cand[keep], lagged[keep]
    baseline = np.maximum(np.nanmedian(lagged, axis=1), floor)
    value = cand["msg_count"].to_numpy(dtype=float) / baseline
    hit_mask = value > ratio
    hit, baseline, value = cand[hit_mask], baseline[hit_mask], value[hit_mask]
    if hit.empty:
        return empty
    ev = [{"msg_count": int(c), "baseline": round(float(b), 2), "ratio": round(float(v), 2),
           "distinct_destinations": int(d)}
          for c, b, v, d in zip(hit["msg_count"], baseline, value, hit["distinct_destinations"], strict=True)]
    return _frame(rule, hit, "sender", hit["source_addr"], pd.Series(value, index=hit.index), ratio, ev)


_EVALUATORS = {
    "repeated_destination": _repeated_destination,
    "repeated_destination_per_sender": _repeated_destination_per_sender,
    "spiking_sender": _spiking_sender,
}


def evaluate_rules(win: Windows, rules: list[FraudRule] | tuple[FraudRule, ...]) -> pd.DataFrame:
    frames = [_EVALUATORS[r.rule_type](win, r) for r in rules if r.enabled]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return pd.DataFrame(columns=HIT_COLUMNS)
    return pd.concat(frames, ignore_index=True)
