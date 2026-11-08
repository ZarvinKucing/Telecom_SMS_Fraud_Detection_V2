"""Synthetic SMS CDR generator with injected, known fraud patterns.

Everything here is fictitious: destinations use the prefix FICTIONAL_PREFIX
(not an assigned country code), clients and senders are invented labels. The
generator returns ground truth so detection rules can be tested for recall and
for false positives on a clean run.
"""
from __future__ import annotations

import random
import uuid
from dataclasses import dataclass

import numpy as np
import pandas as pd

FICTIONAL_PREFIX = "99912"  # 999 is not an assigned E.164 country code
NETWORKS = ("NET_A", "NET_B")
CLIENTS = ("ClientAlpha", "ClientBravo", "ClientCharlie", "ClientDelta", "ClientEcho", "ClientFoxtrot")
PUMP_SENDER = "SNDX01"      # appears only inside the injected burst
HEAVY_SENDER = "SNDH01"     # steady, busy sender that later spikes
PUMP_DESTINATION = FICTIONAL_PREFIX + "9990001"  # outside the normal destination pool
RAW_COLUMNS = [
    "message_id", "received_time", "source_addr", "destination_addr", "network",
    "client_name", "country", "dlr_status", "message_data", "route_label", "category",
]


@dataclass(frozen=True)
class GeneratorConfig:
    seed: int = 1234
    start_date: str = "2026-01-05"
    days: int = 7
    avg_messages_per_hour: int = 150
    n_senders: int = 60
    n_destinations: int = 5000
    inject_fraud: bool = True
    pump_count: int = 60
    spike_count: int = 120
    pump_hour: int = 3
    spike_hour: int = 14


@dataclass(frozen=True)
class GeneratedCdr:
    records: pd.DataFrame  # raw, all strings, as a file would contain
    truth: pd.DataFrame    # injected patterns


def _diurnal(hour: int) -> float:
    return 0.6 + 0.4 * np.sin((hour - 9) * np.pi / 12)


def generate_cdr(cfg: GeneratorConfig | None = None) -> GeneratedCdr:
    cfg = cfg or GeneratorConfig()
    rng = np.random.default_rng(cfg.seed)
    prng = random.Random(cfg.seed)
    senders = np.array([f"SND{i:04d}" for i in range(1, cfg.n_senders + 1)])
    weights = rng.dirichlet(np.full(cfg.n_senders, 20.0))
    start = pd.Timestamp(cfg.start_date)
    frames: list[pd.DataFrame] = []

    def block(window: pd.Timestamp, sender_arr: np.ndarray, dest_arr: np.ndarray,
              network_arr: np.ndarray, client_arr: np.ndarray) -> pd.DataFrame:
        n = len(sender_arr)
        secs = rng.integers(0, 3600, n)
        ts = (window + pd.to_timedelta(secs, unit="s")).strftime("%Y-%m-%d %H:%M:%S")
        return pd.DataFrame({
            "message_id": [str(uuid.UUID(int=prng.getrandbits(128))) for _ in range(n)],
            "received_time": np.asarray(ts),
            "source_addr": sender_arr,
            "destination_addr": dest_arr,
            "network": network_arr,
            "client_name": client_arr,
            "country": "ZZ",
            "dlr_status": rng.choice(["DELIVERED", "FAILED"], n, p=[0.93, 0.07]),
            "message_data": "***REMOVED***",
            "route_label": [f"ROUTE_{r}" for r in rng.integers(1, 5, n)],
            "category": [f"CAT_{c}" for c in rng.integers(1, 4, n)],
        })

    def pool_dest(n: int) -> np.ndarray:
        return np.array([f"{FICTIONAL_PREFIX}{i:07d}" for i in rng.integers(0, cfg.n_destinations, n)])

    for day in range(cfg.days):
        for hour in range(24):
            window = start + pd.Timedelta(days=day, hours=hour)
            factor = _diurnal(hour)
            n = int(rng.poisson(cfg.avg_messages_per_hour * factor))
            idx = rng.choice(cfg.n_senders, n, p=weights)
            frames.append(block(window, senders[idx], pool_dest(n),
                                rng.choice(NETWORKS, n, p=[0.6, 0.4]), np.array(CLIENTS)[idx % len(CLIENTS)]))
            h = int(rng.poisson(7 * factor))
            frames.append(block(window, np.full(h, HEAVY_SENDER), pool_dest(h),
                                np.full(h, "NET_B"), np.full(h, CLIENTS[0])))

    truth_rows: list[dict[str, object]] = []
    if cfg.inject_fraud:
        last = start + pd.Timedelta(days=cfg.days - 1)
        pump_w = last + pd.Timedelta(hours=cfg.pump_hour)
        spike_w = last + pd.Timedelta(hours=cfg.spike_hour)
        n = cfg.pump_count
        frames.append(block(pump_w, np.full(n, PUMP_SENDER), np.full(n, PUMP_DESTINATION),
                            np.full(n, "NET_A"), np.full(n, CLIENTS[1])))
        n = cfg.spike_count
        frames.append(block(spike_w, np.full(n, HEAVY_SENDER), pool_dest(n),
                            np.full(n, "NET_B"), np.full(n, CLIENTS[0])))
        pump_ts = pump_w.tz_localize("UTC")
        spike_ts = spike_w.tz_localize("UTC")
        truth_rows = [
            dict(rule_key="repeated_destination", entity_type="destination",
                 entity_key=PUMP_DESTINATION, network="NET_A", window_start=pump_ts),
            dict(rule_key="repeated_destination_per_sender", entity_type="sender_destination",
                 entity_key=f"{PUMP_SENDER}>{PUMP_DESTINATION}", network="NET_A", window_start=pump_ts),
            dict(rule_key="spiking_sender", entity_type="sender",
                 entity_key=HEAVY_SENDER, network="NET_B", window_start=spike_ts),
        ]

    records = pd.concat(frames, ignore_index=True)
    records = records.sample(frac=1.0, random_state=cfg.seed).reset_index(drop=True)
    truth = pd.DataFrame(truth_rows, columns=["rule_key", "entity_type", "entity_key", "network", "window_start"])
    return GeneratedCdr(records=records[RAW_COLUMNS], truth=truth)
