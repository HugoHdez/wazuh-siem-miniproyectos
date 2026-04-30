#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Escenario kill-chain externo contra `victim` (demo SIEM).
# Orquesta un ataque en 5 etapas encadenadas; cada etapa activa una regla
# Snort específica (SIDs 1010101..1010105) y Wazuh agrupa las etapas del
# mismo origen en alertas HIGH (100390) / CRITICAL (100391).
# Uso: ./scripts/run-snort-chain-scenario.sh [victim] [8080]
# =============================================================================

TARGET_HOST="${1:-victim}"
TARGET_PORT="${2:-8080}"

banner() { printf '\n============================================================\n%s\n============================================================\n' "$*"; }

banner "Stage 1 (Recon) — ping sweep al objetivo (${TARGET_HOST})"
docker compose exec attacker ping -c 3 "${TARGET_HOST}" || true

banner "Stage 2 (Service discovery) — nmap multi-puerto 22,80,445,3306,${TARGET_PORT}"
docker compose exec attacker nmap -sS -p "22,80,445,3306,${TARGET_PORT}" --max-retries 1 -T4 "${TARGET_HOST}" || true

banner "Stage 3 (Web probe) — acceso a rutas sensibles en ${TARGET_HOST}:${TARGET_PORT}"
for p in /admin /login /.env /phpmyadmin /wp-admin /config; do
  echo " -> ${p}"
  docker compose exec attacker curl -s -o /dev/null -w "    http %{http_code}\n" "http://${TARGET_HOST}:${TARGET_PORT}${p}" || true
done

banner "Stage 4 (Exploit attempt) — SQLi / path-traversal en la URI"
docker compose exec attacker curl -s -o /dev/null "http://${TARGET_HOST}:${TARGET_PORT}/search?q=%27+OR+1=1+--+" || true
docker compose exec attacker curl -s -o /dev/null "http://${TARGET_HOST}:${TARGET_PORT}/index?id=1+UNION+SELECT+1,2,3" || true
docker compose exec attacker curl -s -o /dev/null "http://${TARGET_HOST}:${TARGET_PORT}/file?path=../../../etc/passwd" || true

banner "Stage 5 (Exfiltration/C2) — POST con User-Agent automatizado"
for i in 1 2 3; do
  docker compose exec attacker curl -s -o /dev/null \
    -X POST \
    -A "python-requests/2.28.1" \
    -d "exfil=$(head -c 256 /dev/urandom | base64 | tr -d '\n')" \
    "http://${TARGET_HOST}:${TARGET_PORT}/upload" || true
done

cat <<'EOF'

============================================================
Escenario completo. Qué ver en Wazuh Dashboard (Discover):
------------------------------------------------------------
# 1) Evento Snort bruto (cada etapa, una línea por paquete):
agent.name:"victim-agent" AND location:"/var/log/snort/alert"

# 2) Etapas del kill-chain ya etiquetadas (una por etapa, dedup 60s):
agent.name:"victim-agent" AND rule.id:(100360 OR 100361 OR 100362 OR 100363 OR 100364)

# 3) Correlación final HIGH / CRITICAL (el ataque completo):
agent.name:"victim-agent" AND rule.id:(100390 OR 100391)
============================================================
EOF
