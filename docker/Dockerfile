FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential curl wget unzip git python3 python3-venv python3-pip \
    liblua5.1-dev libluajit-5.1-dev luarocks openjdk-11-jre-headless ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r /tmp/requirements.txt

RUN luarocks install lua-cjson

RUN curl -L -o /usr/local/bin/stylua "https://github.com/JohnnyMorganz/StyLua/releases/download/v0.13.0/stylua-linux" \
 && chmod +x /usr/local/bin/stylua || true

RUN mkdir -p /opt/unluac \
 && curl -L -o /opt/unluac/unluac.jar https://github.com/Anaminus/unluac/releases/download/v1.2/unluac.jar

ENV PATH="/opt/venv/bin:${PATH}"
