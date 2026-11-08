"""Hourly aggregation. Memory is bounded by the aggregates, not the raw rows."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class Windows:
    destination: pd.DataFrame         # window_start, network, destination_addr, msg_count, distinct_senders
    sender_destination: pd.DataFrame  # window_start, network, source_addr, destination_addr, msg_count
    sender: pd.DataFrame              # window_start, network, source_addr, msg_count, distinct_destinations


def build_windows(records: pd.DataFrame, network_scope: Sequence[str] = ()) -> Windows:
    df = records[["received_time", "network", "source_addr", "destination_addr"]].copy()
    if network_scope:
        wanted = {n.lower() for n in network_scope}
        df = df[df["network"].str.lower().isin(wanted)]
    df["window_start"] = df["received_time"].dt.floor("h")
    destination = (df.groupby(["window_start", "network", "destination_addr"], sort=True)
                   .agg(msg_count=("source_addr", "size"), distinct_senders=("source_addr", "nunique"))
                   .reset_index())
    sender_destination = (df.groupby(["window_start", "network", "source_addr", "destination_addr"], sort=True)
                          .size().rename("msg_count").reset_index())
    sender = (df.groupby(["window_start", "network", "source_addr"], sort=True)
              .agg(msg_count=("destination_addr", "size"), distinct_destinations=("destination_addr", "nunique"))
              .reset_index())
    return Windows(destination, sender_destination, sender)
