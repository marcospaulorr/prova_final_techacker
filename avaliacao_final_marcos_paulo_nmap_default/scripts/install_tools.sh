#!/usr/bin/env bash
set -euo pipefail

echo "[*] Instalando Nmap (obrigatório)"
sudo apt-get update -y
sudo apt-get install -y nmap

echo "[*] (Opcional) Nikto e WhatWeb"
sudo apt-get install -y nikto whatweb || true

echo "[*] (Opcional) ZAP via snap"
snap list | grep zaproxy || sudo snap install zaproxy

echo "[*] (Opcional) ZAP via Docker:"
echo "    docker pull owasp/zap2docker-stable"
