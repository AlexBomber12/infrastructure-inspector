FROM python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server iproute2 procps util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -p x -s /bin/sh audit \
    && mkdir -p /run/sshd \
    && rm -f /etc/ssh/ssh_host_*
COPY host/sg-audit-dispatch.py /opt/host/sg-audit-dispatch.py
CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/run/fixture/sshd_config"]
