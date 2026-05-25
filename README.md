# bumblebee-threat-catalog

Standalone GitHub-native threat catalog repository for [Bumblebee](https://github.com/perplexityai/bumblebee).

This repo avoids Perplexity Computer entirely. Instead, GitHub Actions periodically pulls public malicious-package intelligence, converts it into Bumblebee-compatible exposure catalogs, and opens an update PR when the catalog changes.

## What this repo does

- Pulls structured malicious-package reports from `ossf/malicious-packages`
- Converts OSV records into Bumblebee `catalogs/*.json`
- Publishes machine-readable metadata about each build
- Opens catalog update PRs on a schedule
- Includes local runner scripts so a developer machine can pull the catalog and run Bumblebee on a timer

## Repository layout

```text
.github/workflows/
  update-catalog.yml
  validate.yml
catalogs/
  openssf-malicious-packages.json
  metadata.json
scripts/
  build_bumblebee_catalog.py
  validate_catalog.py
  bumblebee-catalog-watch.sh
  bumblebee-daily-scan.sh
  config.env.example
tests/
  fixtures/
  test_build_catalog.py
deploy/
  launchd/
  systemd/
```

## Catalog shape

The generated catalog follows Bumblebee's current `schema_version: 0.1.0` exposure format:

```json
{
  "schema_version": "0.1.0",
  "_comment": "Generated from OpenSSF malicious-packages OSV records.",
  "entries": [
    {
      "id": "MAL-2026-3329",
      "name": "Malicious code in api-typings (npm)",
      "ecosystem": "npm",
      "package": "api-typings",
      "versions": ["100.2.0"],
      "severity": "critical",
      "source": "https://osv.dev/vulnerability/MAL-2026-3329",
      "indicators": {
        "published": "2026-05-04T16:46:38Z",
        "modified": "2026-05-12T07:30:41Z"
      }
    }
  ]
}
```

## Update workflow

`update-catalog.yml` runs on a schedule and via manual dispatch:

1. Checks out this repository
2. Sparse-checks out `ossf/malicious-packages`
3. Rebuilds `catalogs/openssf-malicious-packages.json`
4. Rebuilds `catalogs/metadata.json`
5. Validates output
6. Opens or updates a PR if files changed

The generated catalog intentionally keeps only exact package/version matches that Bumblebee can use directly. Unsupported ecosystems and records without explicit versions are counted in metadata and skipped.

## Local use with Bumblebee

Install Bumblebee first:

```bash
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest
```

Run a one-off scan against this repo's generated catalog:

```bash
bumblebee scan \
  --profile deep \
  --root "$HOME" \
  --exposure-catalog ./catalogs \
  --findings-only \
  --max-duration 10m
```

For scheduled local scans, copy [scripts/config.env.example](/Users/gosats/Work/bumblebee-threat-catalog/scripts/config.env.example) to `config.env` and use:

- [scripts/bumblebee-catalog-watch.sh](/Users/gosats/Work/bumblebee-threat-catalog/scripts/bumblebee-catalog-watch.sh)
- [scripts/bumblebee-daily-scan.sh](/Users/gosats/Work/bumblebee-threat-catalog/scripts/bumblebee-daily-scan.sh)
- [deploy/launchd/com.example.bumblebee.catalog-watch.plist](/Users/gosats/Work/bumblebee-threat-catalog/deploy/launchd/com.example.bumblebee.catalog-watch.plist)
- [deploy/launchd/com.example.bumblebee.daily-scan.plist](/Users/gosats/Work/bumblebee-threat-catalog/deploy/launchd/com.example.bumblebee.daily-scan.plist)
- [deploy/systemd/bumblebee-catalog-watch.service](/Users/gosats/Work/bumblebee-threat-catalog/deploy/systemd/bumblebee-catalog-watch.service)
- [deploy/systemd/bumblebee-catalog-watch.timer](/Users/gosats/Work/bumblebee-threat-catalog/deploy/systemd/bumblebee-catalog-watch.timer)
- [deploy/systemd/bumblebee-daily-scan.service](/Users/gosats/Work/bumblebee-threat-catalog/deploy/systemd/bumblebee-daily-scan.service)
- [deploy/systemd/bumblebee-daily-scan.timer](/Users/gosats/Work/bumblebee-threat-catalog/deploy/systemd/bumblebee-daily-scan.timer)

## Local development

Build catalogs from a checked-out source feed:

```bash
python3 scripts/build_bumblebee_catalog.py \
  --input-dir /path/to/malicious-packages/osv/malicious \
  --output-dir ./catalogs
```

Validate generated artifacts:

```bash
python3 scripts/validate_catalog.py catalogs/openssf-malicious-packages.json catalogs/metadata.json
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Scheduler setup

macOS `launchd`:

1. Copy the two plist files from `deploy/launchd/` into `~/Library/LaunchAgents/`
2. Replace `/ABSOLUTE/PATH/TO/REPO` with the local clone path
3. Load them:

```bash
launchctl unload ~/Library/LaunchAgents/com.example.bumblebee.catalog-watch.plist 2>/dev/null || true
launchctl unload ~/Library/LaunchAgents/com.example.bumblebee.daily-scan.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.example.bumblebee.catalog-watch.plist
launchctl load ~/Library/LaunchAgents/com.example.bumblebee.daily-scan.plist
```

Linux `systemd --user`:

1. Copy the four files from `deploy/systemd/` into `~/.config/systemd/user/`
2. Replace `/ABSOLUTE/PATH/TO/REPO` with the local clone path
3. Enable timers:

```bash
systemctl --user daemon-reload
systemctl --user enable --now bumblebee-catalog-watch.timer
systemctl --user enable --now bumblebee-daily-scan.timer
```

Cron fallback:

```cron
5 * * * * BUMBLEBEE_CONFIG=/ABSOLUTE/PATH/TO/REPO/scripts/config.env /ABSOLUTE/PATH/TO/REPO/scripts/bumblebee-catalog-watch.sh
30 10,16 * * * BUMBLEBEE_CONFIG=/ABSOLUTE/PATH/TO/REPO/scripts/config.env /ABSOLUTE/PATH/TO/REPO/scripts/bumblebee-daily-scan.sh
```

## Source assumptions

- Primary feed: `ossf/malicious-packages`
- Target scanner: `perplexityai/bumblebee`
- Exact version matching only
- Read-only local scanning only; no remediation or package-manager execution
