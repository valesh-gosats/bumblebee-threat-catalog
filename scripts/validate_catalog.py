#!/usr/bin/env python3
"""Validate generated Bumblebee catalog artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_catalog(catalog: dict) -> list[str]:
    errors: list[str] = []
    if catalog.get("schema_version") != "0.1.0":
        errors.append("catalog.schema_version must equal 0.1.0")

    entries = catalog.get("entries")
    if not isinstance(entries, list):
        return ["catalog.entries must be a list"]

    seen_ids: set[str] = set()
    for index, entry in enumerate(entries):
        prefix = f"entries[{index}]"
        for field in ("id", "name", "ecosystem", "package", "severity", "source"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                errors.append(f"{prefix}.{field} must be a non-empty string")

        versions = entry.get("versions")
        if not isinstance(versions, list) or not versions:
            errors.append(f"{prefix}.versions must be a non-empty list")
        elif any(not isinstance(version, str) or not version.strip() for version in versions):
            errors.append(f"{prefix}.versions must contain non-empty strings")

        entry_id = entry.get("id")
        if isinstance(entry_id, str):
            if entry_id in seen_ids:
                errors.append(f"{prefix}.id is duplicated: {entry_id}")
            seen_ids.add(entry_id)

    return errors


def validate_metadata(metadata: dict) -> list[str]:
    errors: list[str] = []
    if metadata.get("schema_version") != "1":
        errors.append("metadata.schema_version must equal 1")

    source = metadata.get("source")
    if not isinstance(source, dict):
        errors.append("metadata.source must be an object")

    stats = metadata.get("stats")
    if not isinstance(stats, dict):
        errors.append("metadata.stats must be an object")
    else:
        for field in (
            "scanned_files",
            "scanned_records",
            "emitted_entries",
            "skipped_unsupported_ecosystem",
            "skipped_missing_versions",
            "skipped_missing_package",
        ):
            value = stats.get(field)
            if not isinstance(value, int) or value < 0:
                errors.append(f"metadata.stats.{field} must be a non-negative integer")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: validate_catalog.py <catalog.json> <metadata.json>", file=sys.stderr)
        return 2

    catalog = read_json(Path(argv[1]))
    metadata = read_json(Path(argv[2]))
    errors = validate_catalog(catalog) + validate_metadata(metadata)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("catalog validation OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

