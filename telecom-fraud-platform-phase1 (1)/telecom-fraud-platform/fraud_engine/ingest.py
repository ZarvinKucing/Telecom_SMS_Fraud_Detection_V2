"""Idempotent, failure-safe file ingestion.

Order of operations fixes the original defect (file moved before the insert):
  1. hash the file; skip if that hash is already committed
  2. validate/normalize
  3. load in ONE atomic store transaction
  4. only after commit, move the file to the processed directory
A failure at step 2 or 3 leaves the source file where it was.
"""
from __future__ import annotations

import hashlib
import logging
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import pandas as pd

from fraud_engine.normalize import SchemaError, normalize_frame

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class BatchInfo:
    batch_id: str
    file_name: str
    file_sha256: str
    rows_read: int


@dataclass(frozen=True)
class LoadResult:
    rows_loaded: int  # excludes rows whose message_id already existed


class RecordStore(Protocol):
    def batch_exists(self, file_sha256: str) -> bool: ...

    def load_batch(self, batch: BatchInfo, records: pd.DataFrame, rejected: pd.DataFrame) -> LoadResult:
        """Atomic: either the batch, its records and rejects are all stored, or none are."""
        ...


@dataclass(frozen=True)
class IngestResult:
    file_name: str
    status: str  # loaded | skipped_duplicate_file | invalid_schema | failed
    rows_read: int = 0
    rows_loaded: int = 0
    rows_rejected: int = 0
    error: str | None = None


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _archive(path: Path, processed_dir: Path, sha: str) -> None:
    processed_dir.mkdir(parents=True, exist_ok=True)
    target = processed_dir / path.name
    if target.exists():
        target = processed_dir / f"{sha[:12]}_{path.name}"
    shutil.move(str(path), str(target))


def ingest_file(path: Path, store: RecordStore, processed_dir: Path, source_tz: str = "UTC") -> IngestResult:
    sha = sha256_of(path)
    if store.batch_exists(sha):
        _archive(path, processed_dir, sha)  # data is already committed, safe to archive
        log.info("duplicate file skipped", extra={"file": path.name})
        return IngestResult(path.name, "skipped_duplicate_file")
    try:
        raw = pd.read_csv(path, dtype=str, keep_default_na=False)
        norm = normalize_frame(raw, source_tz)
    except SchemaError as exc:
        log.error("invalid schema", extra={"file": path.name, "error": str(exc)})
        return IngestResult(path.name, "invalid_schema", error=str(exc))
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError) as exc:
        log.error("unreadable file", extra={"file": path.name, "error": str(exc)})
        return IngestResult(path.name, "failed", error=f"unreadable file: {exc}")

    batch = BatchInfo(str(uuid.uuid4()), path.name, sha, len(raw))
    try:
        loaded = store.load_batch(batch, norm.good, norm.rejected)
    except Exception as exc:  # store contract: rolled back, file stays in the input folder
        log.error("load failed, file left in place", extra={"file": path.name, "error": str(exc)})
        return IngestResult(path.name, "failed", len(raw), 0, len(norm.rejected), str(exc))
    try:
        _archive(path, processed_dir, sha)
    except OSError as exc:  # committed but not moved: next run sees the hash and archives it
        log.warning("archive failed after commit", extra={"file": path.name, "error": str(exc)})
    log.info("file loaded", extra={"file": path.name, "loaded": loaded.rows_loaded,
                                   "rejected": len(norm.rejected), "at": datetime.now(UTC).isoformat()})
    return IngestResult(path.name, "loaded", len(raw), loaded.rows_loaded, len(norm.rejected))


def ingest_folder(input_dir: Path, store: RecordStore, processed_dir: Path,
                  source_tz: str = "UTC") -> list[IngestResult]:
    return [ingest_file(p, store, processed_dir, source_tz) for p in sorted(input_dir.glob("*.csv"))]
