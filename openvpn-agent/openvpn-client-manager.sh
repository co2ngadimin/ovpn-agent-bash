#!/bin/bash
# Skrip ini menggunakan path installer yang ditemukan secara dinamis.
OPENVPN_INSTALL_SCRIPT="/root/ubuntu-22.04-lts-vpn-server.sh"

create_client() {
    local username=$1
    if [ -z "$username" ]; then
        echo "⛔ Please provide a username. Usage: $0 create <username>"
        exit 1
    fi
    # Membuat user secara non-interaktif
    printf "1\n%s\n1\n" "$username" | sudo "$OPENVPN_INSTALL_SCRIPT"
    sleep 1
}

revoke_client() {
    local username="$1"
    if [ -z "$username" ]; then exit 1; fi

    # Membaca path index.txt secara dinamis dari file .env
    local index_path="$(grep -oP 'EASY_RSA_INDEX_PATH=\K.*' "/root/openvpn-agent/.env" | tr -d '\"')"
    if [ ! -f "$index_path" ]; then
        echo "⛔ Easy RSA index file not found at '$index_path'."
        exit 1
    fi
    # Mencari nomor klien (case-insensitive)
    local num=$(sudo tail -n +2 "$index_path" | grep "^V" | cut -d '=' -f2 | nl -w1 -s' ' | awk -v name="$username" 'BEGIN{IGNORECASE=1} $2 == name {print $1; exit}')
    
    if [ -z "$num" ]; then 
        echo "⛔ Client '$username' not found or already revoked."
        exit 1
    fi

    # Mencabut user secara non-interaktif
    printf "2\n%s\ny\n" "$num" | sudo "$OPENVPN_INSTALL_SCRIPT"
    sleep 1
}

case "$1" in
    create) create_client "$2" ;;
    revoke) revoke_client "$2" ;;
    *) echo "Usage: $0 {create|revoke} <username>"; exit 1 ;;
esac
