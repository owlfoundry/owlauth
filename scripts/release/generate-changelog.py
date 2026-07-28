#!/usr/bin/env python3
"""Generate deterministic component release notes from squash PR titles."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from changelog import COMPONENT_TAG_PREFIXES, ChangelogError, generate_notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", choices=COMPONENT_TAG_PREFIXES, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()
    try:
        generate_notes(
            component=args.component,
            version=args.version,
            output=args.output,
            reference=args.ref,
        )
    except ChangelogError as error:
        print(f"changelog generation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
