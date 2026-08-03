#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

find "$ROOT" -name "*.c" -o -name "*.h" \
    | xargs clang-format -i

echo "Done."
