"""In-memory RecordStore with the same contract as PostgresStore (used by tests and offline runs)."""
from __future__ import annotations

from datetime import datetime

import pandas as pd

from fraud_engine.ingest import BatchInfo, LoadResult


class InMemoryStore:
    def __init__(self) -> None:
        self.batches: dict[str, BatchInfo] = {}
        self.records: dict[tuple[str, pd.Timestamp], dict[str, object]] = {}
        self.rejected: list[tuple[str, int, str]] = []
        self.fail_next_load: Exception | None = None  # test hook

    def batch_exists(self, file_sha256: str) -> bool:
        return file_sha256 in self.batches

    def load_batch(self, batch: BatchInfo, records: pd.DataFrame, rejected: pd.DataFrame) -> LoadResult:
        if self.fail_next_load is not None:
            exc, self.fail_next_load = self.fail_next_load, None
            raise exc
        # stage first, commit last: nothing is visible until every step succeeded
        staged = {(r["message_id"], r["received_time"]): r for r in records.to_dict("records")
                  if (r["message_id"], r["received_time"]) not in self.records}
        staged_rejects = [(batch.file_sha256, int(r.line_number), r.reason) for r in rejected.itertuples()]
        self.records.update(staged)
        self.rejected.extend(staged_rejects)
        self.batches[batch.file_sha256] = batch
        return LoadResult(rows_loaded=len(staged))

    def to_frame(self) -> pd.DataFrame:
        return pd.DataFrame(list(self.records.values()))

    def fetch_records(self, start: datetime, end: datetime) -> pd.DataFrame:
        """Return the same half-open time window as PostgresStore for worker tests."""
        frame = self.to_frame()
        if frame.empty:
            return pd.DataFrame(columns=["message_id", "received_time", "source_addr", "destination_addr",
                                         "network", "dlr_status"])
        times = pd.to_datetime(frame["received_time"], utc=True)
        return frame.loc[(times >= start) & (times < end)].reset_index(drop=True)
