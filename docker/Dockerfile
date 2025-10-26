FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y \
    build-essential curl wget unzip git python3 python3-venv python3-pip \
    lua5.4 luajit libluajit-5.1-dev luarocks ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Lua JSON (optional but helpful)
RUN luarocks install lua-cjson || true

# Python deps
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r /app/requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"
