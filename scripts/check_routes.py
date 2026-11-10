"""List every route with its required permission; exit 1 if any route declares none.

Usage: python scripts/check_routes.py [--markdown]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.auth.permissions import PERMISSIONS  # noqa: E402
from backend.core import PUBLIC, Router  # noqa: E402
from backend.handlers import router as default_router  # noqa: E402


def check(router: Router) -> list[str]:
    known = {p for perms in PERMISSIONS.values() for p in perms}
    problems = []
    for r in router.routes:
        if not r.permission:
            problems.append(f"{r.method} {r.pattern}: no permission declared")
        elif r.permission != PUBLIC and r.permission not in known:
            problems.append(f"{r.method} {r.pattern}: permission {r.permission!r} is not granted to any role")
        if r.writes and r.permission == PUBLIC:
            problems.append(f"{r.method} {r.pattern}: public state-changing route")
    return problems


def roles_for(permission: str) -> str:
    return ", ".join(sorted(role for role, perms in PERMISSIONS.items() if permission in perms)) or "-"


def main(argv: list[str] | None = None, router: Router = default_router) -> int:
    argv = sys.argv[1:] if argv is None else argv
    problems = check(router)
    if "--markdown" in argv:
        print("| Method | Path | Permission | Roles | Audited | Summary |\n|---|---|---|---|---|---|")
        for r in router.routes:
            who = "anyone" if r.permission == PUBLIC else roles_for(str(r.permission))
            print(f"| {r.method} | `{r.pattern}` | `{r.permission}` | {who} | {'yes' if r.writes else 'no'} | {r.summary} |")
    else:
        for r in router.routes:
            print(f"{r.method:<5} {r.pattern:<38} {r.permission}")
    for p in problems:
        print("ERROR:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
