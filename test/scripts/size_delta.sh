#!/usr/bin/env bash
# size_delta.sh [limit_kb] — size delta of the ntx binary vs the baseline in test/.ntx-size-baseline
# stdout: "Δ size: <cur> − <baseline> = <+Δ> B (<Δ/1024> KB)"
# exit 1 if limit_kb is given and Δ > limit_kb*1024 (prints SIZE LIMIT EXCEEDED)
set -euo pipefail
cd "$(dirname "$0")/../.."

baseline_file="test/.ntx-size-baseline"
if [ ! -f "$baseline_file" ]; then
  echo "ERROR: baseline file not found: $baseline_file" >&2
  exit 1
fi
baseline="$(tr -d '[:space:]' < "$baseline_file")"
if [ ! -f ntx ]; then
  echo "ERROR: ntx binary not found at repo root" >&2
  exit 1
fi
cur="$(stat -c%s ntx)"
delta=$((cur - baseline))
if [ "$delta" -ge 0 ]; then
  signed="+${delta}"
else
  signed="${delta}"
fi
kb="$(awk -v d="$delta" 'BEGIN { printf "%.2f", d / 1024 }')"
echo "Δ size: ${cur} − ${baseline} = ${signed} B (${kb} KB)"

limit_kb="${1:-}"
if [ -n "$limit_kb" ]; then
  case "$limit_kb" in
    ''|*[!0-9]*)
      echo "ERROR: limit_kb must be a non-negative integer, got: $limit_kb" >&2
      exit 1
      ;;
  esac
  limit_bytes=$((limit_kb * 1024))
  if [ "$delta" -gt "$limit_bytes" ]; then
    echo "SIZE LIMIT EXCEEDED"
    exit 1
  fi
fi
exit 0
