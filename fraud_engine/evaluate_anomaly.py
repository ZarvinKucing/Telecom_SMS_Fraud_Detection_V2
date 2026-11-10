"""Measure the Isolation Forest signal against synthetic ground truth (sender-window level)."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import pandas as pd

from fraud_engine.anomaly import AnomalyConfig, anomaly_hits
from fraud_engine.normalize import normalize_frame
from fraud_engine.windows import build_windows
from synthetic_data.generate_cdr import GeneratorConfig, generate_cdr


@dataclass(frozen=True)
class AnomalyEvaluation:
    seeds: int
    true_positives: int
    flagged: int
    positives: int
    windows: int

    @property
    def precision(self) -> float:
        return self.true_positives / self.flagged if self.flagged else 0.0

    @property
    def recall(self) -> float:
        return self.true_positives / self.positives if self.positives else 0.0


def evaluate_anomaly(seeds: Iterable[int], cfg: AnomalyConfig | None = None) -> AnomalyEvaluation:
    cfg = cfg or AnomalyConfig()
    tp = flagged = positives = windows = n = 0
    for seed in seeds:
        n += 1
        gen = generate_cdr(GeneratorConfig(seed=seed))
        win = build_windows(normalize_frame(gen.records).good)
        windows += len(win.sender)
        truth = {(r.entity_key, r.network, r.window_start) for r in gen.truth.itertuples()
                 if r.entity_type == "sender"}
        truth |= {(r.entity_key.split(">")[0], r.network, r.window_start) for r in gen.truth.itertuples()
                  if r.entity_type == "sender_destination"}
        hits = anomaly_hits(win.sender, cfg)
        got = {(r.entity_key, r.network, r.window_start) for r in hits.itertuples()}
        tp += len(got & truth)
        flagged += len(got)
        positives += len(truth)
    return AnomalyEvaluation(n, tp, flagged, positives, windows)
