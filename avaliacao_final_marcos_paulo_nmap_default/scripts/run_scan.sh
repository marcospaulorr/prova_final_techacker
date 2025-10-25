#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then
  echo "Uso: $0 <URL>"
  exit 1
fi
URL="$1"
python app.py --cli --target "$URL"
