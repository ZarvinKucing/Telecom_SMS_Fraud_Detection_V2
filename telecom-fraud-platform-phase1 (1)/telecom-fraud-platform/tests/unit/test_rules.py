import unittest

import pandas as pd

from fraud_engine.normalize import normalize_frame
from fraud_engine.pipeline import run_detection
from fraud_engine.rules import DEFAULT_RULES, FraudRule, evaluate_rules, load_rules
from fraud_engine.windows import build_windows
from synthetic_data.generate_cdr import (HEAVY_SENDER, PUMP_DESTINATION, PUMP_SENDER, GeneratorConfig,
                                         generate_cdr)


def _good(cfg):
    g = generate_cdr(cfg)
    return g, normalize_frame(g.records).good


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dirty_gen, cls.dirty = _good(GeneratorConfig())
        _, cls.clean = _good(GeneratorConfig(inject_fraud=False))

    def hits(self, df, rules=DEFAULT_RULES, scope=()):
        return evaluate_rules(build_windows(df, scope), rules)

    def test_clean_traffic_raises_no_hits(self):
        self.assertEqual(len(self.hits(self.clean)), 0)

    def test_each_rule_flags_its_injected_pattern(self):
        h = self.hits(self.dirty)
        got = {(r.rule_key, r.entity_key, r.network) for r in h.itertuples()}
        want = {(t.rule_key, t.entity_key, t.network) for t in self.dirty_gen.truth.itertuples()}
        self.assertEqual(got, want)

    def test_per_sender_rule_attributes_the_sender(self):
        h = self.hits(self.dirty)
        row = h[h["rule_key"] == "repeated_destination_per_sender"].iloc[0]
        self.assertEqual(row["entity_key"], f"{PUMP_SENDER}>{PUMP_DESTINATION}")

    def test_spike_flagged_against_own_baseline_not_absolute_volume(self):
        h = self.hits(self.dirty)
        row = h[h["rule_key"] == "spiking_sender"].iloc[0]
        self.assertEqual(row["entity_key"], HEAVY_SENDER)
        self.assertGreater(row["evidence"]["ratio"], 5)
        self.assertLess(row["evidence"]["baseline"], 20)

    def test_new_sender_without_history_is_not_a_spike(self):
        h = self.hits(self.dirty)
        spikes = h[h["rule_key"] == "spiking_sender"]
        self.assertNotIn(PUMP_SENDER, set(spikes["entity_key"]))

    def test_spike_not_flagged_when_history_too_short(self):
        short = normalize_frame(generate_cdr(GeneratorConfig(days=3)).records).good  # spike on day 3
        h = self.hits(short)
        self.assertEqual(len(h[h["rule_key"] == "spiking_sender"]), 0)

    def test_threshold_is_configurable(self):
        strict = [FraudRule("repeated_destination", "repeated_destination", {"threshold": 1000}, weight=0.6)]
        self.assertEqual(len(self.hits(self.dirty, strict)), 0)
        loose = [FraudRule("repeated_destination", "repeated_destination", {"threshold": 1}, weight=0.6)]
        self.assertGreater(len(self.hits(self.clean, loose)), 0)

    def test_disabled_rule_is_skipped(self):
        off = [FraudRule("repeated_destination", "repeated_destination", {"threshold": 25}, 0.6, enabled=False)]
        self.assertEqual(len(self.hits(self.dirty, off)), 0)

    def test_network_scope_filters_traffic(self):
        h = self.hits(self.dirty, scope=("net_b",))  # case-insensitive; excludes the NET_A pump
        self.assertEqual(set(h["rule_key"]), {"spiking_sender"})

    def test_rule_validation(self):
        with self.assertRaises(ValueError):
            FraudRule("x", "repeated_destination", {}, 0.5)
        with self.assertRaises(ValueError):
            FraudRule("x", "repeated_destination", {"threshold": -1}, 0.5)
        with self.assertRaises(ValueError):
            FraudRule("x", "repeated_destination", {"threshold": 5}, 1.5)
        with self.assertRaises(ValueError):
            FraudRule("x", "nope", {"threshold": 5}, 0.5)

    def test_load_rules_from_json(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rules.json"
            p.write_text(json.dumps([{"rule_key": "r", "rule_type": "repeated_destination",
                                      "params": {"threshold": 7}, "weight": 0.4, "version": 2}]))
            rules = load_rules(p)
        self.assertEqual((rules[0].params["threshold"], rules[0].version), (7, 2))

    def test_empty_input_does_not_crash(self):
        empty = self.dirty.iloc[0:0]
        self.assertEqual(len(run_detection(empty).alerts), 0)


class EndToEndTests(unittest.TestCase):
    def test_pipeline_recall_and_precision_on_ground_truth(self):
        g, good = _good(GeneratorConfig(seed=99))
        res = run_detection(good)
        found = set(res.alerts["entity_key"])
        truth = set(g.truth["entity_key"])
        self.assertEqual(found, truth)
        self.assertTrue(set(res.alerts["window_start"]) <= set(g.truth["window_start"]))

    def test_rerunning_detection_is_deterministic(self):
        _, good = _good(GeneratorConfig(seed=5))
        a, b = run_detection(good).alerts, run_detection(good).alerts
        self.assertTrue(a.equals(b))

    def test_robust_across_seeds(self):
        for seed in (1, 2, 3, 4):
            g, good = _good(GeneratorConfig(seed=seed))
            self.assertEqual(set(run_detection(good).alerts["entity_key"]), set(g.truth["entity_key"]), seed)
            _, clean = _good(GeneratorConfig(seed=seed, inject_fraud=False))
            self.assertEqual(len(run_detection(clean).alerts), 0, seed)


if __name__ == "__main__":
    unittest.main()
