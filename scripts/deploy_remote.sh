#!/usr/bin/env bash
set -euo pipefail

# Compatibility entrypoint retained for existing callers; canonical script is
# deploy-remote.sh.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/deploy-remote.sh" "$@"
