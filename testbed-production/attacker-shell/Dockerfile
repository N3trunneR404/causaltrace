FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash curl wget netcat-openbsd python3 python3-pip \
      iproute2 iputils-ping dnsutils tcpdump nmap \
      ncat socat openssh-client git ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

# Default entrypoint — add route to prod net, then hold the container open.
RUN printf '%s\n' \
    '#!/bin/bash' \
    '# Route all traffic for ct_prod_net via the ct_attack_net gateway.' \
    'ip route del default 2>/dev/null || true' \
    'ip route add 10.88.0.0/24 via 10.88.1.1 dev eth0 2>/dev/null || true' \
    'ip route add default via 10.88.1.1 2>/dev/null || true' \
    'echo ""' \
    'echo "══════════════════════════════════════════════"' \
    'echo "  CausalTrace Attacker Simulation Shell"' \
    'echo "  Your IP: 10.88.1.100   (UNTRUSTED)"' \
    'echo "  Targets: 10.88.0.0/24  (prod mesh)"' \
    'echo "══════════════════════════════════════════════"' \
    'echo ""' \
    'exec sleep infinity' \
  > /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
