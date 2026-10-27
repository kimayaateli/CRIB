#!/bin/zsh
# ====================================================================
# CRIB — Cyber Range in a Box | Test Runner
# ====================================================================

if [ -n "$ZSH_VERSION" ]; then
    PROJECT_DIR="${0:A:h}"
else
    PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

cd "$PROJECT_DIR" || exit 1

unset PYTHONPATH
unset PYTHONHOME

echo "========================================================"
echo " Running CRIB Pytest Suite"
echo "========================================================"

exec "$PROJECT_DIR/.venv/bin/pytest" -v "$@"
