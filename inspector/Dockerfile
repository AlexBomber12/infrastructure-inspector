FROM python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ARG SOURCE_REVISION
LABEL org.opencontainers.image.version="0.3.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/ssh-inspector

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps -r requirements.lock \
    && python -m pip check

COPY server.py catalog.py bounded.py hosts.py ./

RUN groupadd --gid 65533 inspector && useradd --uid 65533 --gid inspector --home-dir /home/inspector --create-home --shell /usr/sbin/nologin inspector

USER 65533:65533

CMD ["python", "server.py"]
