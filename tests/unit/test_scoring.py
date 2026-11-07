import unittest

import pandas as pd

from fraud_engine.rules import HIT_COLUMNS, severity
from fraud_engine.scoring import ScoringConfig, band_for, combine, score_hits

WS = pd.Timestamp("2026-01-05 03:00", tz="UTC")


def hit(rule, w, s, key="d1", net="NET_A", etype="destination"):
    return dict(rule_key=rule, rule_version=1, weight=w, window_start=WS, network=net, entity_type=etype,
                entity_key=key, observed=0.0, threshold=0.0, severity=s, evidence={})


class ScoringTests(unittest.TestCase):
    def test_single_hit_equals_weight_times_severity(self):
        self.assertAlmostEqual(combine([0.6 * 0.5]), 30.0)

    def test_more_evidence_raises_score(self):
        self.assertGreater(combine([0.3, 0.3]), combine([0.3]))

    def test_never_exceeds_100(self):
        self.assertLessEqual(combine([1.0, 1.0, 1.0]), 100.0)
        self.assertLessEqual(combine([0.9] * 20), 100.0)

    def test_order_independent(self):
        self.assertAlmostEqual(combine([0.2, 0.5, 0.1]), combine([0.1, 0.2, 0.5]))

    def test_severity_curve(self):
        s = severity([26, 50, 500], 25)
        self.assertAlmostEqual(s[0], 0.52)
        self.assertAlmostEqual(s[1], 1.0)
        self.assertAlmostEqual(s[2], 1.0)
        self.assertEqual(float(severity([10], 25)[0]), 0.5 - 0.5 * 15 / 25)

    def test_hits_on_same_entity_are_combined_with_components_kept(self):
        hits = pd.DataFrame([hit("r1", 0.6, 0.5), hit("r2", 0.5, 0.4)], columns=HIT_COLUMNS)
        alerts, comps = score_hits(hits)
        self.assertEqual(len(alerts), 1)
        self.assertAlmostEqual(alerts.loc[0, "risk_score"], 100 * (1 - (1 - 0.3) * (1 - 0.2)))
        self.assertEqual(set(comps["rule_key"]), {"r1", "r2"})
        self.assertTrue((comps["rule_version"] == 1).all())

    def test_different_entities_make_separate_alerts(self):
        hits = pd.DataFrame([hit("r1", 0.6, 1.0, key="a"), hit("r1", 0.6, 1.0, key="b")], columns=HIT_COLUMNS)
        self.assertEqual(len(score_hits(hits)[0]), 2)

    def test_bands(self):
        got = band_for([0, 24.99, 25, 49.9, 50, 74.9, 75, 100], ScoringConfig())
        self.assertEqual(list(got), ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])

    def test_bands_configurable(self):
        self.assertEqual(list(band_for([40], ScoringConfig((10.0, 20.0, 30.0)))), ["critical"])

    def test_empty_hits(self):
        alerts, comps = score_hits(pd.DataFrame(columns=HIT_COLUMNS))
        self.assertTrue(alerts.empty and comps.empty)


if __name__ == "__main__":
    unittest.main()
