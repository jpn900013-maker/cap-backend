#!/bin/bash
# 9Captcha Backend – VPS Start Script
# ---
# IMPORTANT: Must use --workers 1 because:
#   - Playwright keeps a persistent browser in memory
#   - Forking (multiple workers) kills the browser connection
#   - Threads handle concurrency safely instead
#
# --timeout 120: solver tasks can take up to ~60s, default 30s kills them mid-solve

export PORT=${PORT:-5000}

echo "[9Captcha] Starting backend on port $PORT"
echo "[9Captcha] Mode: 1 worker, 4 threads (Playwright-safe)"

exec gunicorn \
    --bind 0.0.0.0:$PORT \
    --workers 1 \
    --threads 4 \
    --timeout 120 \
    --preload \
    --access-logfile - \
    --error-logfile - \
    server:app
