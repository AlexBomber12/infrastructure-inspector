FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables netcat-openbsd iputils-ping python3 \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/multi_network_policy.sh /opt/multi_network_policy.sh
COPY tests/test_multi_network_policy.sh /opt/test_multi_network_policy.sh
CMD ["bash", "/opt/test_multi_network_policy.sh"]
