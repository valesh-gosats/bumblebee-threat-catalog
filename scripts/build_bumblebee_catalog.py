#!/usr/bin/env python3
"""Build a Bumblebee exposure catalog from OpenSSF malicious-packages OSV records."""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BUMBLEBEE_SCHEMA_VERSION = "0.1.0"
SUPPORTED_ECOSYSTEMS = {
    "npm": "npm",
    "PyPI": "pypi",
    "Go": "go",
    "RubyGems": "rubygems",
    "Composer": "packagist",
}


@dataclass
class BuildStats:
    scanned_files: int = 0
    scanned_records: int = 0
    emitted_entries: int = 0
    skipped_unsupported_ecosystem: int = 0
    skipped_missing_versions: int = 0
    skipped_missing_package: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--catalog-name",
        default="openssf-malicious-packages.json",
        help="Filename for the generated Bumblebee catalog.",
    )
    parser.add_argument(
        "--metadata-name",
        default="metadata.json",
        help="Filename for generator metadata output.",
    )
    parser.add_argument(
        "--source-repository",
        default="https://github.com/ossf/malicious-packages",
    )
    parser.add_argument(
        "--source-ref",
        default=os.environ.get("SOURCE_REF", "").strip(),
    )
    parser.add_argument(
        "--generator-version",
        default="1",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def version_list(affected: dict[str, Any]) -> list[str]:
    versions = affected.get("versions") or []
    if not isinstance(versions, list):
        return []
    normalized = [str(version).strip() for version in versions if str(version).strip()]
    return sorted(set(normalized))


def build_entry(record: dict[str, Any], affected: dict[str, Any], position: int) -> dict[str, Any] | None:
    package = affected.get("package") or {}
    package_name = (package.get("name") or "").strip()
    ecosystem = package.get("ecosystem")
    if not package_name or not ecosystem:
        return None

    mapped_ecosystem = SUPPORTED_ECOSYSTEMS.get(ecosystem)
    if not mapped_ecosystem:
        return {"_skip": "unsupported_ecosystem"}

    versions = version_list(affected)
    if not versions:
        return {"_skip": "missing_versions"}

    osv_id = record["id"]
    entry_id = osv_id if position == 0 else f"{osv_id}-{position + 1}"
    summary = (record.get("summary") or f"Malicious package in {package_name}").strip()
    source = f"https://osv.dev/vulnerability/{osv_id}"
    indicators: dict[str, Any] = {}

    for key in ("published", "modified", "withdrawn"):
        value = record.get(key)
        if value:
            indicators[key] = value

    aliases = record.get("aliases") or []
    if aliases:
        indicators["aliases"] = aliases

    database_specific = record.get("database_specific") or {}
    origins = database_specific.get("malicious-packages-origins")
    if origins:
        indicators["origins"] = origins

    return {
        "id": entry_id,
        "name": summary,
        "ecosystem": mapped_ecosystem,
        "package": package_name,
        "versions": versions,
        "severity": "critical",
        "source": source,
        "indicators": indicators,
    }


def iter_osv_records(input_dir: Path) -> list[Path]:
    return sorted(path for path in input_dir.rglob("*.json") if path.is_file())


def build_catalog(input_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    stats = BuildStats()
    entries: list[dict[str, Any]] = []
    ecosystem_counts: Counter[str] = Counter()

    for path in iter_osv_records(input_dir):
        stats.scanned_files += 1
        record = load_json(path)
        stats.scanned_records += 1
        affected_items = record.get("affected") or []

        for position, affected in enumerate(affected_items):
            entry = build_entry(record, affected, position)
            if entry is None:
                stats.skipped_missing_package += 1
                continue
            if "_skip" in entry:
                if entry["_skip"] == "unsupported_ecosystem":
                    stats.skipped_unsupported_ecosystem += 1
                elif entry["_skip"] == "missing_versions":
                    stats.skipped_missing_versions += 1
                continue

            entries.append(entry)
            ecosystem_counts[entry["ecosystem"]] += 1
            stats.emitted_entries += 1

    entries.sort(key=lambda item: (item["ecosystem"], item["package"], item["id"]))
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    catalog = {
        "schema_version": BUMBLEBEE_SCHEMA_VERSION,
        "_comment": (
            "Generated from OpenSSF malicious-packages OSV records. "
            "This catalog is intended for exact Bumblebee package/version matches only."
        ),
        "entries": entries,
    }
    metadata = {
        "schema_version": "1",
        "generated_at": generated_at,
        "source": {
            "name": "OpenSSF malicious-packages",
            "repository": "",
            "ref": "",
        },
        "stats": {
            "scanned_files": stats.scanned_files,
            "scanned_records": stats.scanned_records,
            "emitted_entries": stats.emitted_entries,
            "skipped_unsupported_ecosystem": stats.skipped_unsupported_ecosystem,
            "skipped_missing_versions": stats.skipped_missing_versions,
            "skipped_missing_package": stats.skipped_missing_package,
            "ecosystems": dict(sorted(ecosystem_counts.items())),
        },
    }
    return catalog, metadata


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


def main() -> int:
    args = parse_args()
    catalog, metadata = build_catalog(args.input_dir)
    metadata["source"]["repository"] = args.source_repository
    metadata["source"]["ref"] = args.source_ref
    metadata["generator"] = {
        "name": "build_bumblebee_catalog.py",
        "version": args.generator_version,
    }

    output_dir = args.output_dir
    write_json(output_dir / args.catalog_name, catalog)
    write_json(output_dir / args.metadata_name, metadata)
    print(
        f"Generated {args.catalog_name} with {metadata['stats']['emitted_entries']} entries "
        f"from {metadata['stats']['scanned_records']} records."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

