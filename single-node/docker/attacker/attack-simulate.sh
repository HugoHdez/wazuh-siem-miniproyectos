#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-victim}"
TARGET_PORT="${2:-8080}"

echo "[1/4] Ping test to ${TARGET_HOST}"
ping -c 4 "${TARGET_HOST}" || true

echo "[2/4] TCP SYN scan (1-1024) to ${TARGET_HOST}"
nmap -sS -p 1-1024 "${TARGET_HOST}" || true

echo "[3/4] Targeted service probe on ports 22,80,8080"
nmap -sS -p 22,80,8080 "${TARGET_HOST}" || true

echo "[4/4] HTTP request burst to ${TARGET_HOST}:${TARGET_PORT}"
for _ in $(seq 1 20); do
  curl -s "http://${TARGET_HOST}:${TARGET_PORT}" >/dev/null || true
done

echo "Attack simulation complete."
