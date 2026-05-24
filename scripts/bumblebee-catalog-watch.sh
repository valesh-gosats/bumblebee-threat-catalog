#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${BUMBLEBEE_CONFIG:-$SCRIPT_DIR/config.env}"

if [ -f "$CONFIG" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG"
fi

export PATH="$HOME/go/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

BASE="${BASE:-$HOME/security}"
CATALOG_REPO="${CATALOG_REPO:-$BASE/bumblebee-threat-catalog}"
CATALOG_DIR="${CATALOG_DIR:-$CATALOG_REPO/catalogs}"
OUTDIR="${OUTDIR:-$BASE/bumblebee-runs}"
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_BRANCH="${GIT_BRANCH:-main}"
SCAN_PROFILE="${SCAN_PROFILE:-deep}"
SCAN_ROOT="${SCAN_ROOT:-$HOME}"
MAX_DURATION="${MAX_DURATION:-10m}"
NOTIFY_DESKTOP="${NOTIFY_DESKTOP:-true}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINDINGS="$OUTDIR/findings-$STAMP.ndjson"
LOG="$OUTDIR/catalog-watch-$STAMP.log"
STATUS="failed"
EFFECTIVE_CATALOG_DIR=""
FINDING_COUNT=0

mkdir -p "$OUTDIR"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

count_finding_records() {
  python3 - "$FINDINGS" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
count = 0
if path.exists():
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("record_type") == "finding":
            count += 1
print(count)
PY
}

notify_scan_result() {
  local title body
  if [ "$NOTIFY_DESKTOP" != "true" ]; then
    return 0
  fi

  if [ "$STATUS" = "findings" ]; then
    title="Bumblebee alert"
    if [ "$FINDING_COUNT" -eq 1 ]; then
      body="1 supply-chain exposure detected"
    else
      body="$FINDING_COUNT supply-chain exposures detected"
    fi
  elif [ "$STATUS" = "clean" ]; then
    title="Bumblebee scan complete"
    body="No supply-chain exposures detected"
  else
    title="Bumblebee scan failed"
    body="Check the scan log for details"
  fi

  if command -v osascript >/dev/null 2>&1; then
    osascript -e "display notification \"$body\" with title \"$title\"" || true
    return 0
  fi

  if command -v notify-send >/dev/null 2>&1; then
    notify-send "$title" "$body" || true
    return 0
  fi
}

prepare_catalog_dir() {
  local temp_dir
  temp_dir="$(mktemp -d)"
  find "$CATALOG_DIR" -maxdepth 1 -type f -name '*.json' ! -name 'metadata.json' -exec cp {} "$temp_dir" \;
  EFFECTIVE_CATALOG_DIR="$temp_dir"
  trap 'rm -rf "$EFFECTIVE_CATALOG_DIR"' EXIT
}

summarize_findings() {
  python3 - "$FINDINGS" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists() or path.stat().st_size == 0:
    print("Threat summary: no findings.")
    raise SystemExit(0)

rows = []
for line in path.read_text().splitlines():
    if not line.strip():
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("record_type") != "finding":
        continue
    rows.append(obj)

if not rows:
    print("Threat summary: no findings.")
    raise SystemExit(0)

print(f"Threat summary: {len(rows)} finding(s).")
counts = Counter()
for row in rows:
    key = (
        row.get("catalog_name") or row.get("catalog_id") or "unknown catalog",
        row.get("package_name") or "unknown package",
        row.get("version") or "unknown version",
        row.get("severity") or "unknown severity",
    )
    counts[key] += 1

for idx, ((catalog_name, package_name, version, severity), count) in enumerate(counts.items(), start=1):
    suffix = f" x{count}" if count > 1 else ""
    print(f"  {idx}. [{severity}] {package_name}@{version} matched {catalog_name}{suffix}")
PY
}

run_scan() {
  echo "[$(date -u +%FT%TZ)] Starting catalog watcher"

  command -v git >/dev/null 2>&1 || { echo "git not found in PATH"; exit 1; }
  command -v bumblebee >/dev/null 2>&1 || { echo "bumblebee not found in PATH"; exit 1; }

  if [ ! -d "$CATALOG_REPO/.git" ]; then
    echo "Catalog repo not found: $CATALOG_REPO"
    exit 1
  fi

  if [ ! -d "$CATALOG_DIR" ]; then
    echo "Catalog directory not found: $CATALOG_DIR"
    exit 1
  fi

  prepare_catalog_dir

  cd "$CATALOG_REPO"

  if git rev-parse --verify HEAD >/dev/null 2>&1; then
    OLD_REV="$(git rev-parse HEAD)"
    echo "Local revision: $OLD_REV"
  else
    OLD_REV="UNBORN"
    echo "Local revision: none yet (no commits in local catalog repo)"
  fi

  if git remote get-url "$GIT_REMOTE" >/dev/null 2>&1; then
    if git ls-remote --exit-code --heads "$GIT_REMOTE" "$GIT_BRANCH" >/dev/null 2>&1; then
      git fetch "$GIT_REMOTE" "$GIT_BRANCH"
      NEW_REV="$(git rev-parse FETCH_HEAD)"
      echo "Remote revision: $NEW_REV"

      if [ "$OLD_REV" = "$NEW_REV" ]; then
        echo "Catalog unchanged; continuing with latest local catalog."
      else
        echo "Catalog changed or local repo has no commits; pulling latest catalog."
        git pull --ff-only "$GIT_REMOTE" "$GIT_BRANCH"
        prepare_catalog_dir
      fi
    else
      echo "Remote branch $GIT_REMOTE/$GIT_BRANCH not found yet; continuing with local catalog."
    fi
  else
    echo "Git remote '$GIT_REMOTE' is not configured; continuing with local catalog."
  fi

  echo "Running Bumblebee scan."
  bumblebee scan \
    --profile "$SCAN_PROFILE" \
    --root "$SCAN_ROOT" \
    --exposure-catalog "$EFFECTIVE_CATALOG_DIR" \
    --findings-only \
    --max-duration "$MAX_DURATION" \
    > "$FINDINGS"

  FINDING_COUNT="$(count_finding_records)"
  if [ "$FINDING_COUNT" -gt 0 ]; then
    echo "FINDINGS DETECTED: $FINDINGS"
    STATUS="findings"
  else
    echo "No Bumblebee findings."
    STATUS="clean"
  fi

  echo "[$(date -u +%FT%TZ)] Finished catalog watcher"
}

run_scan
notify_scan_result

echo "Bumblebee catalog watch $STATUS. Log: $LOG"
echo "Findings file: $FINDINGS"
summarize_findings
