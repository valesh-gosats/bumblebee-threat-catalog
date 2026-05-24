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
DAILY_SCAN_PROFILE="${DAILY_SCAN_PROFILE:-deep}"
DAILY_SCAN_ROOT="${DAILY_SCAN_ROOT:-$HOME}"
DAILY_MAX_DURATION="${DAILY_MAX_DURATION:-30m}"
NOTIFY_DESKTOP="${NOTIFY_DESKTOP:-true}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINDINGS="$OUTDIR/daily-findings-$STAMP.ndjson"
LOG="$OUTDIR/daily-scan-$STAMP.log"
STATUS="failed"
EFFECTIVE_CATALOG_DIR=""

mkdir -p "$OUTDIR"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

notify_findings() {
  if [ "$NOTIFY_DESKTOP" != "true" ]; then
    return 0
  fi

  if command -v osascript >/dev/null 2>&1; then
    osascript -e 'display notification "Bumblebee found supply-chain exposure(s)" with title "Bumblebee alert"' || true
    return 0
  fi

  if command -v notify-send >/dev/null 2>&1; then
    notify-send "Bumblebee alert" "Supply-chain exposure found" || true
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

run_scan() {
  echo "[$(date -u +%FT%TZ)] Starting daily scan"

  command -v bumblebee >/dev/null 2>&1 || { echo "bumblebee not found in PATH"; exit 1; }

  if [ ! -d "$CATALOG_DIR" ]; then
    echo "Catalog directory not found: $CATALOG_DIR"
    exit 1
  fi

  prepare_catalog_dir

  echo "Using local catalog directory: $CATALOG_DIR"
  echo "Running Bumblebee scan."

  bumblebee scan \
    --profile "$DAILY_SCAN_PROFILE" \
    --root "$DAILY_SCAN_ROOT" \
    --exposure-catalog "$EFFECTIVE_CATALOG_DIR" \
    --findings-only \
    --max-duration "$DAILY_MAX_DURATION" \
    > "$FINDINGS"

  if [ -s "$FINDINGS" ]; then
    echo "FINDINGS DETECTED: $FINDINGS"
    notify_findings
    STATUS="findings"
  else
    echo "No Bumblebee findings."
    STATUS="clean"
  fi

  echo "[$(date -u +%FT%TZ)] Finished daily scan"
}

run_scan

echo "Bumblebee daily scan $STATUS. Log: $LOG"
if [ "$STATUS" = "findings" ]; then
  echo "Findings: $FINDINGS"
fi
