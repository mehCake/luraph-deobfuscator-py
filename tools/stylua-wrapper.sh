#!/usr/bin/env bash
set -euo pipefail

if ! command -v stylua >/dev/null 2>&1; then
  echo "stylua not available; skipping format" >&2
  exit 0
fi

stylua "$@"
