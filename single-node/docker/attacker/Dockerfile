FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    curl \
    nmap \
    netcat-openbsd \
    hping3 \
    dnsutils \
    bash \
    && rm -rf /var/lib/apt/lists/*

COPY docker/attacker/attack-simulate.sh /usr/local/bin/attack-simulate.sh
RUN chmod +x /usr/local/bin/attack-simulate.sh

ENTRYPOINT ["bash", "-lc", "sleep infinity"]
