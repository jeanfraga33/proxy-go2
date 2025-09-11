#!/bin/bash

# Verifica se o sistema é Ubuntu ou Debian
if ! grep -Eq "ID=(ubuntu|debian)" /etc/os-release; then
    echo "Este script suporta apenas Ubuntu ou Debian. Operação interrompida."
    exit 1
fi

# Função para instalar dependências
install_dependencies() {
    echo "Verificando dependências..."
    sudo apt update
    if ! command -v go &> /dev/null; then
        echo "Instalando Go..."
        sudo apt install -y golang-go
    fi
    if ! command -v git &> /dev/null; then
        echo "Instalando Git..."
        sudo apt install -y git
    fi
    echo "Dependências verificadas/instaladas."
}

# Função para instalar o proxy
install_proxy() {
    # Verifica se o proxyfull já está instalado; se sim, avisa que será atualizado
    if command -v proxyfull &> /dev/null; then
        echo "Proxyfull já instalado. Desinstalando versão anterior para atualizar."
        sudo rm -f /usr/local/bin/proxyfull
        rm -f cert.pem key.pem
        echo "Versão anterior e certificados removidos."
    fi

    # Baixa o repositório temporariamente
    TEMP_DIR="/tmp/proxy-go2"
    rm -rf "$TEMP_DIR"
    echo "Clonando repositório..."
    git clone https://github.com/jeanfraga33/proxy-go2.git "$TEMP_DIR"
    cd "$TEMP_DIR" || exit 1

    # Instala dependências Go
    echo "Instalando dependências Go..."
    go mod init proxy-go2 || true
    go get github.com/gorilla/websocket

    # Compila o binário
    echo "Compilando proxy..."
    go build -o proxyfull proxy-worker.go

    # Instala no sistema
    sudo mv proxyfull /usr/local/bin/
    echo "Proxy instalado com sucesso em /usr/local/bin/proxyfull."
    echo "Execute 'proxyfull' para iniciar."

    # Limpa o diretório temporário
    cd /
    rm -rf "$TEMP_DIR"
}

# Função para desinstalar o proxy
uninstall_proxy() {
    if command -v proxyfull &> /dev/null; then
        echo "Desinstalando proxyfull..."
        sudo rm -f /usr/local/bin/proxyfull
        echo "Proxyfull removido de /usr/local/bin/proxyfull."
    else
        echo "Proxyfull não está instalado."
    fi
    # Remove certificados, se existirem
    rm -f cert.pem key.pem
    echo "Certificados (cert.pem, key.pem) removidos, se existiam."
}

# Menu interativo
while true; do
    echo -e "\n=== Instalador do Proxyfull ==="
    echo "1. Instalar/Atualizar Proxyfull"
    echo "2. Desinstalar Proxyfull"
    echo "3. Sair"
    read -p "Escolha uma opção: " option
    case $option in
        1)
            install_dependencies
            install_proxy
            ;;
        2)
            uninstall_proxy
            ;;
        3)
            echo "Saindo..."
            exit 0
            ;;
        *)
            echo "Opção inválida."
            ;;
    esac
done
