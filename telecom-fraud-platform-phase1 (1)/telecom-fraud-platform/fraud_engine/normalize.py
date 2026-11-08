"""Validation and normalization of raw CDR rows.

Pure functions over DataFrames so they can be tested without a database.
The message body is dropped here and never reaches storage.
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

REQUIRED_COLUMNS = ("message_id", "received_time", "source_addr", "destination_addr", "network")
OPTIONAL_TYPED = ("client_name", "country", "dlr_status")
DROPPED_COLUMNS = ("message_data", "message_text", "message_body", "text")
# Map alternative source headers to canonical names. Extend when real feeds are onboarded.
COLUMN_ALIASES = {"msg_id": "message_id", "timestamp": "received_time", "sender": "source_addr",
                  "destination": "destination_addr", "operator": "network"}
GOOD_COLUMNS = ["message_id", "received_time", "source_addr", "destination_addr", "network",
                "client_name", "country", "dlr_status", "extra"]
_OFFSET = r"(?:Z|[+-]\d{2}:?\d{2})$"


class SchemaError(ValueError):
    """The file lacks required columns; no row can be processed."""


@dataclass(frozen=True)
class NormalizeResult:
    good: pd.DataFrame      # GOOD_COLUMNS, received_time tz-aware UTC
    rejected: pd.DataFrame  # line_number, reason


def _parse_times(raw: pd.Series, source_tz: str) -> pd.Series:
    has_offset = raw.str.contains(_OFFSET, regex=True)
    out = pd.Series(pd.NaT, index=raw.index, dtype="datetime64[ns, UTC]")
    aware = raw[has_offset]
    if len(aware):
        out.loc[aware.index] = pd.to_datetime(aware, errors="coerce", format="ISO8601", utc=True).astype(
            "datetime64[ns, UTC]")
    naive = raw[~has_offset]
    if len(naive):
        parsed = pd.to_datetime(naive, errors="coerce", format="ISO8601")
        localized = parsed.dt.tz_localize(source_tz, ambiguous="NaT", nonexistent="NaT").dt.tz_convert("UTC")
        out.loc[naive.index] = localized.astype("datetime64[ns, UTC]")
    return out


def normalize_frame(raw: pd.DataFrame, source_tz: str = "UTC") -> NormalizeResult:
    df = raw.rename(columns=lambda c: str(c).strip().lower())
    df = df.rename(columns=COLUMN_ALIASES)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise SchemaError(f"missing required columns: {', '.join(missing)}")
    df = df.copy()
    df["line_number"] = range(2, len(df) + 2)  # header is line 1
    known = set(REQUIRED_COLUMNS) | set(OPTIONAL_TYPED) | set(DROPPED_COLUMNS) | {"line_number"}
    extra_cols = [c for c in df.columns if c not in known]
    for col in (*REQUIRED_COLUMNS, *OPTIONAL_TYPED, *extra_cols):
        if col not in df.columns:
            df[col] = ""
        df[col] = df[col].fillna("").astype(str).str.strip()

    df["destination_addr"] = (df["destination_addr"].str.replace(r"[\s\-()]", "", regex=True)
                              .str.lstrip("+"))
    df["source_addr"] = df["source_addr"].str.replace(r"^\+(?=\d+$)", "", regex=True)
    df["received_time"] = _parse_times(df["received_time"], source_tz)

    reason = pd.Series("", index=df.index, dtype="object")

    def flag(mask: pd.Series, text: str) -> None:
        reason.loc[mask & (reason == "")] = text

    flag(df["message_id"] == "", "missing_message_id")
    flag(df["message_id"].str.len() > 64, "message_id_too_long")
    flag(df["received_time"].isna(), "invalid_received_time")
    flag(~df["source_addr"].str.fullmatch(r"[A-Za-z0-9._+\-]{1,40}"), "invalid_source_addr")
    flag(~df["destination_addr"].str.fullmatch(r"\d{6,20}"), "invalid_destination_addr")
    flag(df["network"] == "", "missing_network")
    valid = df[reason == ""]
    dup_idx = valid.index[valid["message_id"].duplicated(keep="first")]
    reason.loc[dup_idx] = "duplicate_message_id_in_file"

    ok = reason == ""
    good = df.loc[ok].copy()
    for col in OPTIONAL_TYPED:
        good[col] = good[col].where(good[col] != "", None)
    if extra_cols:
        good["extra"] = [{k: v for k, v in row.items() if v != ""}
                         for row in good[extra_cols].to_dict("records")]
    else:
        good["extra"] = [{} for _ in range(len(good))]
    rejected = pd.DataFrame({"line_number": df.loc[~ok, "line_number"].astype(int),
                             "reason": reason[~ok]}).reset_index(drop=True)
    return NormalizeResult(good=good[GOOD_COLUMNS].reset_index(drop=True), rejected=rejected)
