"""Command line: generate | analyze (offline, no DB) | ingest | detect (PostgreSQL)."""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd

from common.config import Settings
from common.logging import configure_logging
from fraud_engine.ingest import ingest_folder
from fraud_engine.memory_store import InMemoryStore
from fraud_engine.pipeline import run_detection
from fraud_engine.rules import DEFAULT_RULES, load_rules
from synthetic_data.generate_cdr import GeneratorConfig, generate_cdr

log = logging.getLogger("fraud_engine.cli")


def _cmd_generate(a: argparse.Namespace) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    gen = generate_cdr(GeneratorConfig(seed=a.seed, days=a.days, inject_fraud=not a.clean))
    gen.records.to_csv(out / f"synthetic_cdr_seed{a.seed}.csv", index=False)
    (out / "ground_truth.json").write_text(gen.truth.to_json(orient="records", date_format="iso", indent=2))
    log.info("generated", extra={"rows": len(gen.records), "dir": str(out)})
    return 0


def _write_results(out_dir: Path, alerts: pd.DataFrame, components: pd.DataFrame) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(out_dir / "alerts.csv", index=False)
    (out_dir / "components.json").write_text(components.to_json(orient="records", date_format="iso", indent=2))


def _cmd_analyze(a: argparse.Namespace) -> int:
    s = Settings.from_env()
    store = InMemoryStore()
    results = ingest_folder(Path(a.input), store, Path(a.processed or s.processed_dir), s.source_timezone)
    rules = load_rules(a.rules) if a.rules else DEFAULT_RULES
    res = run_detection(store.to_frame(), rules, network_scope=s.network_scope) if store.records else None
    if res is None:
        log.warning("no records loaded")
        return 1
    _write_results(Path(a.out or s.output_dir), res.alerts, res.components)
    print(json.dumps([r.__dict__ for r in results], indent=2))
    print(res.alerts.to_string(index=False))
    return 0


def _cmd_ingest(a: argparse.Namespace) -> int:
    from fraud_engine.pg_store import PostgresStore, make_engine  # lazy: needs SQLAlchemy + PostgreSQL
    s = Settings.from_env()
    store = PostgresStore(make_engine(s.require_database_url()))
    results = ingest_folder(Path(a.input or s.input_dir), store, Path(s.processed_dir), s.source_timezone)
    print(json.dumps([r.__dict__ for r in results], indent=2))
    return 0 if all(r.status in {"loaded", "skipped_duplicate_file"} for r in results) else 1


def _cmd_detect(a: argparse.Namespace) -> int:
    from fraud_engine.pg_store import PostgresStore, make_engine
    s = Settings.from_env()
    store = PostgresStore(make_engine(s.require_database_url()))
    rules = load_rules(a.rules) if a.rules else DEFAULT_RULES
    records = store.fetch_records(datetime.fromisoformat(a.since), datetime.fromisoformat(a.until))
    res = run_detection(records, rules, network_scope=s.network_scope)
    store.save_detection(rules, res.alerts, res.components)
    print(f"{len(res.alerts)} alerts saved")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fraud_engine")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write a synthetic CDR CSV")
    g.add_argument("--out", required=True)
    g.add_argument("--seed", type=int, default=1234)
    g.add_argument("--days", type=int, default=7)
    g.add_argument("--clean", action="store_true", help="no injected fraud")
    g.set_defaults(fn=_cmd_generate)
    an = sub.add_parser("analyze", help="offline: ingest to memory, detect, write alerts (no database)")
    an.add_argument("--input", required=True)
    an.add_argument("--out")
    an.add_argument("--processed")
    an.add_argument("--rules")
    an.set_defaults(fn=_cmd_analyze)
    ig = sub.add_parser("ingest", help="load a folder of CSVs into PostgreSQL")
    ig.add_argument("--input")
    ig.set_defaults(fn=_cmd_ingest)
    d = sub.add_parser("detect", help="run rules over a time range in PostgreSQL")
    d.add_argument("--since", required=True)
    d.add_argument("--until", required=True)
    d.add_argument("--rules")
    d.set_defaults(fn=_cmd_detect)
    args = p.parse_args(argv)
    configure_logging(Settings.from_env().log_level)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
