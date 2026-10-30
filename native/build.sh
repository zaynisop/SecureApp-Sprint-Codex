#!/usr/bin/env bash
# Convenience wrapper around the Makefile (Linux/macOS).
set -euo pipefail
cd "$(dirname "$0")"
make secure
echo "Built thumbgen_secure.so"
