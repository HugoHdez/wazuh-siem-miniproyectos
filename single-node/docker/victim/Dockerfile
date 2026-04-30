FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gpg \
    gnupg \
    lsb-release \
    software-properties-common \
    iproute2 \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    nmap \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Wazuh agent from official repository.
RUN mkdir -p /usr/share/keyrings \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" WAZUH_AGENT_NAME="victim-agent" apt-get install -y wazuh-agent \
    && rm -rf /var/lib/apt/lists/*

# Install Snort from Ubuntu repository.
RUN apt-get update \
    && echo "snort snort/address_range string any" | debconf-set-selections \
    && echo "snort snort/interface string eth0" | debconf-set-selections \
    && apt-get install -y --no-install-recommends snort \
    && rm -rf /var/lib/apt/lists/*

COPY docker/victim/snort-lab-chain.rules /etc/snort/rules/lab-chain.rules
COPY docker/victim/victim-entrypoint.sh /usr/local/bin/victim-entrypoint.sh
RUN chmod +x /usr/local/bin/victim-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/victim-entrypoint.sh"]
