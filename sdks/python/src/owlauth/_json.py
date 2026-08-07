"""Strict bounded JSON decoding shared by Runtime and conformance inputs."""

from __future__ import annotations

import json
import math


def loads_strict_json(body: bytes) -> object:
    """Decode RFC JSON and reject non-scalar Unicode or non-finite numbers."""
    value = json.loads(
        body.decode("utf-8"),
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )
    _validate_values(value)
    return value


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(value)
    return parsed


def _validate_values(value: object) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
