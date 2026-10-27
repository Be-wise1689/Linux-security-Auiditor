#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=========================================="
echo " Linux Security Configuration Auditor"
echo "=========================================="

# Check Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3 is required."
    exit 1
fi

# Create virtual environment automatically
if [[ ! -d .venv ]]; then
    echo "[1/3] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/3] Virtual environment already exists."
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies only when needed
if [[ ! -f .venv/.requirements-installed || requirements.txt -nt .venv/.requirements-installed ]]; then
    echo "[2/3] Installing project dependencies..."
    python -m pip install -r requirements.txt
    touch .venv/.requirements-installed
else
    echo "[2/3] Dependencies already installed."
fi

echo "[3/3] Starting the auditor..."
echo "Dashboard: http://127.0.0.1:8000"
echo "API docs:  http://127.0.0.1:8000/docs"
echo "Press Ctrl+C to stop."
echo "=========================================="

exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
