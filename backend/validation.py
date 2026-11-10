"""Strict request validation. Runs before any handler or database access."""
from __future__ import annotations

import math
import re
from collections.abc import Iterable
from typing import Any

_MISSING = object()


class ValidationError(Exception):
    def __init__(self, errors: list[dict[str, str]]) -> None:
        super().__init__("validation failed")
        self.errors = errors


class Checker:
    """Validates one source (path params, query string, or JSON body). `text=True` for string sources."""

    def __init__(self, data: Any, *, text: bool = False, where: str = "body") -> None:
        self.errors: list[dict[str, str]] = []
        self.out: dict[str, Any] = {}
        self.text, self.where, self._seen = text, where, set()
        if data is None:
            data = {}
        if not isinstance(data, dict):
            self._err("", "must be a JSON object")
            data = {}
        self.data: dict[str, Any] = data

    def _err(self, key: str, msg: str) -> None:
        self.errors.append({"loc": f"{self.where}.{key}" if key else self.where, "msg": msg})

    def _get(self, key: str, required: bool, default: Any) -> Any:
        self._seen.add(key)
        value = self.data.get(key, _MISSING)
        if value is _MISSING or value is None:
            if required:
                self._err(key, "field required")
            else:
                self.out[key] = default
            return _MISSING
        return value

    def string(self, key: str, *, max_len: int, min_len: int = 0, pattern: str | None = None,
               required: bool = True, default: Any = None) -> None:
        v = self._get(key, required, default)
        if v is _MISSING:
            return
        if not isinstance(v, str):
            return self._err(key, "must be a string")
        if not min_len <= len(v) <= max_len:
            return self._err(key, f"length must be between {min_len} and {max_len}")
        if pattern and not re.fullmatch(pattern, v):
            return self._err(key, "invalid format")
        self.out[key] = v

    def integer(self, key: str, *, lo: int, hi: int, required: bool = True, default: Any = None) -> None:
        v = self._get(key, required, default)
        if v is _MISSING:
            return
        if self.text:
            if not isinstance(v, str) or not re.fullmatch(r"-?\d{1,18}", v):
                return self._err(key, "must be an integer")
            v = int(v)
        elif isinstance(v, bool) or not isinstance(v, int):
            return self._err(key, "must be an integer")
        if not lo <= v <= hi:
            return self._err(key, f"must be between {lo} and {hi}")
        self.out[key] = v

    def number(self, key: str, *, lo: float, hi: float, required: bool = True, default: Any = None) -> None:
        v = self._get(key, required, default)
        if v is _MISSING:
            return
        if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v):
            return self._err(key, "must be a finite number")
        if not lo < v <= hi:
            return self._err(key, f"must be greater than {lo} and at most {hi}")
        self.out[key] = float(v)

    def boolean(self, key: str, *, default: bool = False) -> None:
        v = self._get(key, False, default)
        if v is _MISSING:
            return
        if self.text and isinstance(v, str) and v.lower() in {"true", "false"}:
            v = v.lower() == "true"
        if not isinstance(v, bool):
            return self._err(key, "must be a boolean")
        self.out[key] = v

    def enum(self, key: str, choices: Iterable[str], *, required: bool = True, default: Any = None) -> None:
        v = self._get(key, required, default)
        if v is _MISSING:
            return
        if not isinstance(v, str) or v not in set(choices):
            return self._err(key, f"must be one of {sorted(set(choices))}")
        self.out[key] = v

    def int_list(self, key: str, *, min_items: int, max_items: int, lo: int, hi: int) -> None:
        v = self._get(key, True, None)
        if v is _MISSING:
            return
        if not isinstance(v, list) or not min_items <= len(v) <= max_items:
            return self._err(key, f"must be a list of {min_items}-{max_items} integers")
        if any(isinstance(i, bool) or not isinstance(i, int) or not lo <= i <= hi for i in v):
            return self._err(key, f"items must be integers between {lo} and {hi}")
        if len(set(v)) != len(v):
            return self._err(key, "items must be unique")
        self.out[key] = list(v)

    def number_map(self, key: str, *, max_items: int) -> None:
        v = self._get(key, True, None)
        if v is _MISSING:
            return
        if not isinstance(v, dict) or not 1 <= len(v) <= max_items:
            return self._err(key, f"must be an object with 1-{max_items} entries")
        for k, n in v.items():
            if not isinstance(k, str) or not re.fullmatch(r"[a-z_]{1,64}", k):
                return self._err(key, "invalid parameter name")
            if isinstance(n, bool) or not isinstance(n, int | float) or not math.isfinite(n):
                return self._err(key, f"parameter {k} must be a finite number")
        self.out[key] = dict(v)

    def finish(self) -> None:
        for extra in sorted(set(self.data) - self._seen):
            self._err(str(extra)[:64], "unexpected field")


def finish_all(*checkers: Checker) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    out: dict[str, Any] = {}
    for c in checkers:
        c.finish()
        errors += c.errors
        out.update(c.out)
    if errors:
        raise ValidationError(errors)
    return out


def paging(c: Checker) -> None:
    c.integer("limit", lo=1, hi=200, required=False, default=50)
    c.integer("offset", lo=0, hi=1_000_000, required=False, default=0)
