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

  if [ -s "$FINDINGS" ]; then
    echo "FINDINGS DETECTED: $FINDINGS"
    notify_findings
    STATUS="findings"
  else
    echo "No Bumblebee findings."
    STATUS="clean"
  fi

  echo "[$(date -u +%FT%TZ)] Finished catalog watcher"
}

run_scan

echo "Bumblebee catalog watch $STATUS. Log: $LOG"
if [ "$STATUS" = "findings" ]; then
  echo "Findings: $FINDINGS"
fi
