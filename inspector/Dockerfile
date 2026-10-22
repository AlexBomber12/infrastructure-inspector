FROM python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/ssh-inspector

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt     && python -m pip check

COPY server.py catalog.py bounded.py ./

RUN groupadd --gid 65533 inspector && useradd --uid 65533 --gid inspector --home-dir /home/inspector --create-home --shell /usr/sbin/nologin inspector

USER 65533:65533

CMD ["python", "server.py"]
