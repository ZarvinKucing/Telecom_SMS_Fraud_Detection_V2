import unittest
from datetime import UTC, datetime

import numpy as np
import pandas as pd

from backend.memory_repo import MemoryRepo
from fraud_engine.anomaly import AnomalyConfig, anomaly_hits, build_features, score_windows
from fraud_engine.evaluate_anomaly import evaluate_anomaly
from fraud_engine.memory_store import InMemoryStore
from fraud_engine.normalize import normalize_frame
from fraud_engine.pipeline import run_detection
from fraud_engine.rule_registry import seed_default_rules
from fraud_engine.windows import build_windows
from fraud_engine.worker import run_cycle
from synthetic_data.generate_cdr import HEAVY_SENDER, GeneratorConfig, generate_cdr


def good(seed=1, inject=True):
    return normalize_frame(generate_cdr(GeneratorConfig(seed=seed, inject_fraud=inject)).records).good


class AnomalyTests(unittest.TestCase):
    def test_features_are_finite(self):
        f = build_features(build_windows(good()).sender)
        self.assertTrue(np.isfinite(f.to_numpy()).all())

    def test_too_few_windows_skips_the_model(self):
        sender = build_windows(good()).sender.head(50)
        self.assertTrue(anomaly_hits(sender, AnomalyConfig()).empty)

    def test_scores_are_deterministic_percentiles(self):
        sender = build_windows(good()).sender
        a, b = score_windows(sender, AnomalyConfig()), score_windows(sender, AnomalyConfig())
        self.assertTrue(a.equals(b))
        self.assertTrue(((a > 0) & (a <= 1)).all())

    def test_default_mode_never_creates_alerts_on_its_own(self):
        clean = good(inject=False)
        self.assertEqual(len(run_detection(clean, anomaly=AnomalyConfig()).alerts), 0)

    def test_standalone_mode_would_flood_alerts_which_is_why_it_is_off(self):
        clean = good(inject=False)
        noisy = run_detection(clean, anomaly=AnomalyConfig(corroborate_only=False)).alerts
        self.assertGreater(len(noisy), 10)

    def test_corroboration_raises_score_of_rule_flagged_entity(self):
        g = good()
        base = run_detection(g).alerts.set_index("entity_key")["risk_score"]
        both = run_detection(g, anomaly=AnomalyConfig())
        boosted = both.alerts.set_index("entity_key")["risk_score"]
        self.assertGreater(boosted[HEAVY_SENDER], base[HEAVY_SENDER])
        self.assertEqual(set(boosted.index), set(base.index))  # no new alerts
        comps = both.components[both.components["entity_key"] == HEAVY_SENDER]
        self.assertEqual(set(comps["rule_key"]), {"spiking_sender", "anomaly_isolation_forest"})

    def test_measured_standalone_quality_is_recorded_and_bounded(self):
        # Honest regression guard, not a quality claim: ~0.50 recall at ~0.02 precision measured on seeds 1-10.
        e = evaluate_anomaly(range(1, 11))
        self.assertEqual(e.positives, 20)
        self.assertGreaterEqual(e.recall, 0.35)
        self.assertLess(e.precision, 0.2)  # if this ever fails, update docs/anomaly-evaluation.md


class WorkerTests(unittest.TestCase):
    START, END = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 2, 1, tzinfo=UTC)

    def _loaded_store(self):
        store = InMemoryStore()
        from pathlib import Path
        import tempfile
        from fraud_engine.ingest import ingest_file
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.csv"
            generate_cdr(GeneratorConfig(seed=1)).records.to_csv(p, index=False)
            ingest_file(p, store, Path(d) / "done")
        return store

    def test_cycle_persists_alerts_and_is_idempotent(self):
        store, repo = self._loaded_store(), MemoryRepo()
        n1 = run_cycle(store, repo, repo, self.START, self.END)
        ids = sorted(repo.alerts)
        n2 = run_cycle(store, repo, repo, self.START, self.END)
        self.assertEqual((n1, n2, sorted(repo.alerts)), (3, 3, ids))
        self.assertEqual(len(repo.rules), 3)  # seeded once

    def test_rerun_keeps_case_links(self):
        store, repo = self._loaded_store(), MemoryRepo()
        run_cycle(store, repo, repo, self.START, self.END)
        aid = min(repo.alerts)
        repo.alerts[aid]["case_id"] = 7
        run_cycle(store, repo, repo, self.START, self.END)
        self.assertEqual(repo.alerts[aid]["case_id"], 7)

    def test_cycle_uses_current_rule_versions_from_the_repo(self):
        store, repo = self._loaded_store(), MemoryRepo()
        seed_default_rules(repo)
        repo.add_rule_version("repeated_destination", "repeated_destination", {"threshold": 1000}, 0.6, True)
        run_cycle(store, repo, repo, self.START, self.END)
        keys = {a["entity_type"] for a in repo.alerts.values()}
        self.assertNotIn("destination", keys)
        comp_versions = {c["rule_version"] for cs in repo.components.values() for c in cs}
        self.assertEqual(comp_versions, {1})

    def test_disabled_rule_is_not_evaluated(self):
        store, repo = self._loaded_store(), MemoryRepo()
        seed_default_rules(repo)
        repo.add_rule_version("spiking_sender", "spiking_sender", repo.get_latest_rule("spiking_sender")["params"], 0.5, False)
        run_cycle(store, repo, repo, self.START, self.END)
        self.assertNotIn("sender", {a["entity_type"] for a in repo.alerts.values()})

    def test_time_window_limits_records(self):
        store, repo = self._loaded_store(), MemoryRepo()
        n = run_cycle(store, repo, repo, datetime(2026, 1, 5, tzinfo=UTC), datetime(2026, 1, 6, tzinfo=UTC))
        self.assertEqual(n, 0)

    def test_empty_source_does_not_crash(self):
        repo = MemoryRepo()
        self.assertEqual(run_cycle(InMemoryStore(), repo, repo, self.START, self.END), 0)


if __name__ == "__main__":
    unittest.main()
