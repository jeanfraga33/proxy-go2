#!/bin/bash

# Verifica se o sistema é Ubuntu ou Debian
if ! grep -Eq "ID=(ubuntu|debian)" /etc/os-release; then
    echo "Este script suporta apenas Ubuntu ou Debian. Instalação interrompida."
    exit 1
fi

# Atualiza pacotes e instala dependências se necessário (Go e Git)
sudo apt update
if ! command -v go &> /dev/null; then
    sudo apt install -y golang-go
fi
if ! command -v git &> /dev/null; then
    sudo apt install -y git
fi

# Verifica se o proxyfull já está instalado; se sim, desinstala
if command -v proxyfull &> /dev/null; then
    sudo rm /usr/local/bin/proxyfull
    echo "Versão anterior desinstalada."
fi

# Baixa o repositório temporariamente
TEMP_DIR="/tmp/proxy-go2"
rm -rf "$TEMP_DIR"
git clone https://github.com/jeanfraga33/proxy-go2.git "$TEMP_DIR"
cd "$TEMP_DIR"

# Instala dependências Go
go mod init proxy-go2 || true  # Inicializa módulo se necessário
go get github.com/gorilla/websocket

# Compila o binário
go build -o proxyfull proxy-worker.go

# Instala no sistema
sudo mv proxyfull /usr/local/bin/
echo "Proxy instalado com sucesso. Execute 'proxyfull' para iniciar."

# Limpa o diretório temporário
cd /
rm -rf "$TEMP_DIR"
