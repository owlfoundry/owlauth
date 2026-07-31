"""Strict loader for the shared language-neutral conformance corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from owlauth.errors import ProtocolError


@dataclass(frozen=True, slots=True)
class ConformanceCase:
    name: str
    fixture_path: Path
    fixture: Any
    expected: Any
    definition: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ConformanceCorpus:
    schema_version: int
    cases: tuple[ConformanceCase, ...]


def load_conformance_corpus(path: str | Path) -> ConformanceCorpus:
    """Load and validate shared cases without allowing path escape or duplicate names."""
    source = Path(path).resolve()
    base = source.parent.resolve()
    allowed_root = base.parent.resolve()
    document = _read_json(source)
    if not isinstance(document, dict) or set(document) != {"schemaVersion", "cases"}:
        raise _invalid()
    version = document.get("schemaVersion")
    if not isinstance(version, int) or isinstance(version, bool) or version != 2:
        raise ProtocolError("unsupported_conformance_schema", "Unsupported conformance schema.")
    definitions = document.get("cases")
    if not isinstance(definitions, list):
        raise _invalid()
    names: set[str] = set()
    cases: list[ConformanceCase] = []
    for definition_value in definitions:
        if not isinstance(definition_value, dict) or not all(
            isinstance(key, str) for key in definition_value
        ):
            raise _invalid()
        definition = dict(definition_value)
        allowed_fields = {
            "name",
            "fixture",
            "required",
            "capability",
            "operation",
            "minimumCorpusSchema",
            "configuredContext",
            "expected",
        }
        if set(definition) - allowed_fields:
            raise _invalid()
        name = definition.get("name")
        fixture_ref = definition.get("fixture")
        if (
            not isinstance(name, str)
            or not (1 <= len(name) <= 128)
            or name in names
            or not isinstance(fixture_ref, str)
            or not (1 <= len(fixture_ref) <= 256)
        ):
            raise _invalid()
        required = definition.get("required")
        capability = definition.get("capability")
        operation = definition.get("operation")
        minimum = definition.get("minimumCorpusSchema")
        expected = definition.get("expected")
        if (
            not isinstance(required, bool)
            or not isinstance(capability, str)
            or not isinstance(operation, str)
            or minimum != 2
            or not isinstance(expected, dict)
        ):
            raise _invalid()
        names.add(name)
        fixture_path = (base / fixture_ref).resolve()
        if fixture_path != allowed_root and allowed_root not in fixture_path.parents:
            raise ProtocolError("conformance_path_escape", "Conformance fixture path escapes root.")
        fixture = _read_json(fixture_path)
        fixture_fields = {
            "schemaVersion",
            "synthetic",
            "responseStatus",
            "response",
            "redactionSentinels",
        }
        if not isinstance(fixture, dict) or set(fixture) - fixture_fields:
            raise _invalid()
        response_status = fixture.get("responseStatus")
        sentinels = fixture.get("redactionSentinels", [])
        if (
            fixture.get("schemaVersion") != 2
            or fixture.get("synthetic") is not True
            or not isinstance(response_status, int)
            or isinstance(response_status, bool)
            or not 100 <= response_status <= 599
            or not isinstance(fixture.get("response"), dict)
            or not isinstance(sentinels, list)
            or not all(isinstance(value, str) and 1 <= len(value) <= 256 for value in sentinels)
        ):
            raise _invalid()
        cases.append(
            ConformanceCase(
                name=name,
                fixture_path=fixture_path,
                fixture=fixture,
                expected=definition.get("expected"),
                definition=definition,
            )
        )
    return ConformanceCorpus(schema_version=version, cases=tuple(cases))


def _read_json(path: Path) -> Any:
    try:
        body = path.read_bytes()
        if len(body) > 1_048_576:
            raise _invalid()
        return json.loads(body.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _invalid() from error


def _invalid() -> ProtocolError:
    return ProtocolError("invalid_conformance_corpus", "The conformance corpus is invalid.")
