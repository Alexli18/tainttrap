#!/usr/bin/env bash
# Lock dependencies and export hashed requirement files (NFR-13, research R-08).
set -euo pipefail
cd "$(dirname "$0")/.."
uv lock
uv export --no-dev --format requirements.txt -o requirements.lock
uv export --no-dev --extra cpu --format requirements.txt -o requirements-cpu.lock
