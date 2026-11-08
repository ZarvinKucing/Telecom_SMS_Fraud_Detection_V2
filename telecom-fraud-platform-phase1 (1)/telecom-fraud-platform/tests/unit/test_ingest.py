import tempfile
import unittest
from pathlib import Path

from fraud_engine.ingest import ingest_file, ingest_folder
from fraud_engine.memory_store import InMemoryStore
from synthetic_data.generate_cdr import GeneratorConfig, generate_cdr


class IngestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.inbox, self.done = root / "in", root / "done"
        self.inbox.mkdir()
        self.records = generate_cdr(GeneratorConfig(days=2)).records
        self.store = InMemoryStore()

    def _write(self, name, df=None):
        path = self.inbox / name
        (self.records if df is None else df).to_csv(path, index=False)
        return path

    def test_second_ingest_of_same_content_leaves_counts_unchanged(self):
        self._write("a.csv")
        first = ingest_folder(self.inbox, self.store, self.done)[0]
        count = len(self.store.records)
        self._write("a_copy.csv")  # identical bytes, different name
        second = ingest_folder(self.inbox, self.store, self.done)[0]
        self.assertEqual(first.status, "loaded")
        self.assertEqual(second.status, "skipped_duplicate_file")
        self.assertEqual(len(self.store.records), count)

    def test_overlapping_message_ids_are_not_duplicated(self):
        self._write("a.csv")
        ingest_folder(self.inbox, self.store, self.done)
        n = len(self.store.records)
        self._write("b.csv", self.records.head(100).assign(source_addr="OTHER"))  # same ids, new bytes
        result = ingest_folder(self.inbox, self.store, self.done)[0]
        self.assertEqual(result.status, "loaded")
        self.assertEqual(result.rows_loaded, 0)
        self.assertEqual(len(self.store.records), n)

    def test_failed_load_leaves_source_file_in_input_folder(self):
        path = self._write("a.csv")
        self.store.fail_next_load = RuntimeError("db down")
        result = ingest_file(path, self.store, self.done)
        self.assertEqual(result.status, "failed")
        self.assertTrue(path.exists())
        self.assertEqual(len(self.store.records), 0)
        self.assertFalse(self.store.batches)

    def test_retry_after_failure_succeeds_and_does_not_lose_data(self):
        path = self._write("a.csv")
        self.store.fail_next_load = RuntimeError("db down")
        ingest_file(path, self.store, self.done)
        retry = ingest_file(path, self.store, self.done)
        self.assertEqual(retry.status, "loaded")
        self.assertEqual(retry.rows_loaded, len(self.records))
        self.assertFalse(path.exists())
        self.assertTrue((self.done / "a.csv").exists())

    def test_invalid_schema_file_is_left_in_place(self):
        path = self._write("bad.csv", self.records.drop(columns=["network"]))
        result = ingest_file(path, self.store, self.done)
        self.assertEqual(result.status, "invalid_schema")
        self.assertTrue(path.exists())

    def test_rejected_rows_are_recorded_not_loaded(self):
        bad = self.records.head(10).copy()
        bad.loc[0, "destination_addr"] = "abc"
        path = self._write("a.csv", bad)
        result = ingest_file(path, self.store, self.done)
        self.assertEqual((result.rows_loaded, result.rows_rejected), (9, 1))
        self.assertEqual(self.store.rejected[0][1:], (2, "invalid_destination_addr"))


if __name__ == "__main__":
    unittest.main()
