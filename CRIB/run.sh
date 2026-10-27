#!/bin/zsh
# ====================================================================
# CRIB — Cyber Range in a Box | One-Click Startup Script
# ====================================================================

# Resolve directory in both zsh and bash
if [ -n "$ZSH_VERSION" ]; then
    PROJECT_DIR="${0:A:h}"
else
    PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
fi

cd "$PROJECT_DIR" || exit 1

# Clear any conflicting external Python environment variables
unset PYTHONPATH
unset PYTHONHOME

echo "========================================================"
echo " Starting CRIB — Cyber Range in a Box"
echo " Working Directory: $PROJECT_DIR"
echo " Local URL:         http://127.0.0.1:5001"
echo "========================================================"

exec "$PROJECT_DIR/.venv/bin/python" app.py
