#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/start-analyze-winget-pkgs.sh [--fresh|--resume] [REPORT_PATH] [LOG_PATH]

Modes:
  --resume (default)  Resume from REPORT_PATH using --resume-from
  --fresh             Start a new run and write REPORT_PATH using --report

Examples:
  ./scripts/start-analyze-winget-pkgs.sh
  ./scripts/start-analyze-winget-pkgs.sh --fresh
  ./scripts/start-analyze-winget-pkgs.sh --fresh installer-analysis-report.json analyze-winget-pkgs.log
EOF
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="resume"
REPORT_PATH="installer-analysis-report.json"
LOG_PATH="analyze-winget-pkgs.log"
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh)
      MODE="fresh"
      shift
      ;;
    --resume)
      MODE="resume"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POSITIONAL_ARGS+=("$1")
        shift
      done
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL_ARGS[@]} -gt 2 ]]; then
  echo "Too many positional arguments." >&2
  usage >&2
  exit 2
fi

if [[ ${#POSITIONAL_ARGS[@]} -ge 1 ]]; then
  REPORT_PATH="${POSITIONAL_ARGS[0]}"
fi

if [[ ${#POSITIONAL_ARGS[@]} -ge 2 ]]; then
  LOG_PATH="${POSITIONAL_ARGS[1]}"
fi

cd "$ROOT_DIR"

existing="$(
  ps -eo pid,cmd \
    | grep -E 'target/release/komac analyze-winget-pkgs|cargo run --release analyze-winget-pkgs' \
    | grep -v -- '--markdown-report' \
    | grep -v grep \
    || true
)"
if [[ -n "$existing" ]]; then
  echo "analyze-winget-pkgs appears to already be running:"
  echo "$existing"
  exit 0
fi

export ROOT_DIR REPORT_PATH MODE

nohup setsid bash -lc '
  cd "$ROOT_DIR"
  trap "" TERM

  if [[ "$MODE" == "fresh" ]]; then
    exec cargo run --release analyze-winget-pkgs --report "$REPORT_PATH"
  fi

  exec cargo run --release analyze-winget-pkgs --resume-from "$REPORT_PATH"
' > "$LOG_PATH" 2>&1 < /dev/null &

launcher_pid=$!
echo "Started analyze-winget-pkgs launcher PID: $launcher_pid"
echo "Mode: $MODE"
echo "Report: $ROOT_DIR/$REPORT_PATH"
echo "Log: $ROOT_DIR/$LOG_PATH"
echo "Use: tail -f $ROOT_DIR/$LOG_PATH"
