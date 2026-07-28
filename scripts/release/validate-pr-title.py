#!/usr/bin/env python3
"""Validate the repository pull-request title convention."""

from __future__ import annotations

import argparse
import sys

from changelog import ChangelogError, parse_title


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("title")
    args = parser.parse_args()
    try:
        parse_title(args.title)
    except ChangelogError as error:
        print(f"invalid pull request title: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
