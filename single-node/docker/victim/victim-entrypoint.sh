#!/usr/bin/env bash
set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-victim-agent}"
MONITOR_INTERFACE="${MONITOR_INTERFACE:-eth0}"
ENROLL_MAX_RETRIES="${ENROLL_MAX_RETRIES:-30}"
ENROLL_RETRY_INTERVAL="${ENROLL_RETRY_INTERVAL:-5}"

mkdir -p /var/log/snort /opt/victim-www
echo "victim node online: $(date -u)" > /opt/victim-www/index.html

append_localfile() {
  local location="$1"
  local alias_name="$2"
  local log_format="$3"

  if ! grep -q "<alias>${alias_name}</alias>" /var/ossec/etc/ossec.conf; then
    sed -i "/<\/ossec_config>/i\\
  <localfile>\\
    <log_format>${log_format}</log_format>\\
    <location>${location}</location>\\
    <alias>${alias_name}</alias>\\
  </localfile>" /var/ossec/etc/ossec.conf
  fi
}

# Keep exactly one Snort localfile block and parse fast alerts with snort-full.
python3 - <<'PY'
from pathlib import Path
import re

path = Path("/var/ossec/etc/ossec.conf")
text = path.read_text()
pattern = re.compile(
    r"<localfile>\s*<log_format>[^<]+</log_format>\s*"
    r"<location>/var/log/snort/alert</location>\s*"
    r"<alias>snort-alerts</alias>\s*</localfile>\s*",
    re.MULTILINE,
)
path.write_text(pattern.sub("", text))
PY

touch /var/log/snort/alert
append_localfile "/var/log/snort/alert" "snort-alerts" "snort-full"

enroll_agent_with_retry() {
  if [ -s /var/ossec/etc/client.keys ]; then
    return 0
  fi

  echo "Waiting for Wazuh enrollment service at ${WAZUH_MANAGER}:1515 ..."
  for attempt in $(seq 1 "${ENROLL_MAX_RETRIES}"); do
    if (echo >"/dev/tcp/${WAZUH_MANAGER}/1515") >/dev/null 2>&1; then
      echo "Enrollment service is reachable. Registering agent..."
      if /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${WAZUH_AGENT_NAME}"; then
        echo "Agent enrollment completed."
        return 0
      fi
    fi

    if [ "${attempt}" -eq "${ENROLL_MAX_RETRIES}" ]; then
      echo "Enrollment retry limit reached. Agent will continue and reconnect later."
      return 0
    fi
    sleep "${ENROLL_RETRY_INTERVAL}"
  done
}

/var/ossec/bin/wazuh-control start

if [ -f /etc/snort/rules/local.rules ] && [ -f /etc/snort/rules/lab-chain.rules ] \
  && ! grep -q "sid:1010101" /etc/snort/rules/local.rules; then
  cat /etc/snort/rules/lab-chain.rules >> /etc/snort/rules/local.rules
fi

if [ -f /etc/snort/rules/local.rules ] && ! grep -q "sid:1000001" /etc/snort/rules/local.rules; then
  cat <<'EOF' >> /etc/snort/rules/local.rules
alert icmp any any -> any any (msg:"ICMP test traffic detected"; sid:1000001; rev:1; classtype:misc-activity;)
alert tcp any any -> any 8080 (msg:"HTTP request detected on victim"; sid:1000002; rev:1; classtype:misc-activity;)
EOF
fi

# -k none: skip checksum validation. Docker bridges deliver packets with
# TCP checksum offload delegated to hardware, and Snort may drop HTTP traffic
# silently without this option.
snort -i "${MONITOR_INTERFACE}" -A fast -k none -q -c /etc/snort/snort.conf -l /var/log/snort \
  >/var/log/snort/snort.stdout.log 2>/var/log/snort/snort.stderr.log &

python3 -m http.server 8080 --directory /opt/victim-www &

enroll_agent_with_retry &

wait
