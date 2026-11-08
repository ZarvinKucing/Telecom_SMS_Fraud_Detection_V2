import unittest

from synthetic_data.generate_cdr import FICTIONAL_PREFIX, GeneratorConfig, generate_cdr


class GeneratorTests(unittest.TestCase):
    def test_deterministic_for_same_seed(self):
        a = generate_cdr(GeneratorConfig(seed=7, days=2)).records
        b = generate_cdr(GeneratorConfig(seed=7, days=2)).records
        self.assertTrue(a.equals(b))

    def test_all_destinations_use_fictitious_prefix(self):
        g = generate_cdr(GeneratorConfig(days=2))
        self.assertTrue(g.records["destination_addr"].str.startswith(FICTIONAL_PREFIX).all())

    def test_no_message_content_generated(self):
        g = generate_cdr(GeneratorConfig(days=2))
        self.assertEqual(set(g.records["message_data"]), {"***REMOVED***"})

    def test_message_ids_unique(self):
        g = generate_cdr(GeneratorConfig(days=2))
        self.assertTrue(g.records["message_id"].is_unique)

    def test_truth_present_only_when_injecting(self):
        self.assertEqual(len(generate_cdr(GeneratorConfig(days=7)).truth), 3)
        self.assertEqual(len(generate_cdr(GeneratorConfig(days=7, inject_fraud=False)).truth), 0)


if __name__ == "__main__":
    unittest.main()
