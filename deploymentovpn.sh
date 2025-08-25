#!/bin/bash
#
# deploymentovpn.sh (Unified Version with SNMP)
#
# Skrip ini mengotomatiskan deployment OpenVPN Agent pada server baru.
# Ini akan menginstal dependensi, mengkonfigurasi SNMP, membuat Python virtual environment (venv),
# menyebarkan skrip agen dan manajer klien, dan mengkonfigurasinya untuk
# dijalankan dengan PM2 dari dalam venv.
#
# Usage: sudo ./deploymentovpn.sh
#
# Keluar segera jika ada perintah yang keluar dengan status non-nol.
set -e

# --- Konfigurasi Default ---
PYTHON_AGENT_SCRIPT_NAME="main.py"
CLIENT_MANAGER_SCRIPT_NAME="openvpn-client-manager.sh"
OPENVPN_INSTALL_SCRIPT_PATH="/root/ubuntu-22.04-lts-vpn-server.sh"
NODE_VERSION="v22.17.1"
NODE_DIR="node-$NODE_VERSION-linux-x64"
NODE_URL="https://nodejs.org/dist/$NODE_VERSION/$NODE_DIR.tar.gz"

# Dapatkan nama pengguna yang menjalankan sudo
SUDO_USER=${SUDO_USER:-$(whoami)}
# --- SOLUSI: Tentukan direktori berdasarkan lokasi skrip saat ini ---
# Dapatkan path absolut dari direktori tempat skrip ini berada
BASE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# Tentukan direktori kerja utama di dalam lokasi tersebut
SCRIPT_DIR="$BASE_DIR/openvpn-agent"
VENV_PATH="$SCRIPT_DIR/venv" ## PERUBAHAN VENV: Definisikan path venv
EASY_RSA_INDEX_PATH=""
EASY_RSA_SERVER_NAME_PATH=""

# Variabel yang akan diisi oleh input user
AGENT_API_KEY=""
APP_NAME=""
DASHBOARD_API_URL=""
SERVER_ID=""
OVPN_DIR=""
# Variabel untuk SNMP
CONFIGURE_SNMP="N"
SNMP_COMMUNITY_STRING=""
DASHBOARD_MONITORING_IP=""

# --- Fungsi ---

# Periksa apakah skrip dijalankan dengan hak akses root (sudo)
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "⛔ Tolong jalankan skrip ini dengan sudo: sudo $0"
        exit 1
    fi
    echo "✅ Skrip dijalankan dengan hak akses root."
}

# Fungsi untuk meminta input dari user
get_user_input() {
    echo ""
    while [ -z "$APP_NAME" ]; do
        read -p "🏷️ Masukkan Nama Aplikasi untuk PM2 (contoh: vpn-agent): " APP_NAME
        if [ -z "$APP_NAME" ]; then
            echo "⛔ Nama aplikasi tidak boleh kosong."
        fi
    done

    echo ""
    while [ -z "$AGENT_API_KEY" ]; do
        read -p "🔑 Masukkan AGENT_API_KEY (pastikan sama dengan di dashboard): " AGENT_API_KEY
        if [ -z "$AGENT_API_KEY" ]; then
            echo "⛔ API Key tidak boleh kosong."
        fi
    done

    local url_type_valid=0
    local DASHBOARD_HOST_RAW="" # Raw input from user
    local PROTOCOL=""
    local BASE_URL="" # Akan menyimpan protocol://host[:port]

    while [ $url_type_valid -eq 0 ]; do
        echo ""
        echo "Pilih jenis alamat Dashboard API:"
        echo "1) Alamat IP (contoh: 192.168.1.42)"
        echo "2) Nama Domain (contoh: dashboard.example.com)"
        read -p "Pilihan Anda (1 atau 2): " URL_CHOICE

        case "$URL_CHOICE" in
            1)
                local ip_valid=0
                while [ $ip_valid -eq 0 ]; do
                    read -p "🌐 Masukkan Alamat IP Dashboard API: " DASHBOARD_HOST_RAW
                    if [[ $DASHBOARD_HOST_RAW =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                        echo "🔎 Melakukan ping ke $DASHBOARD_HOST_RAW..."
                        if ping -c 1 -W 1 "$DASHBOARD_HOST_RAW" > /dev/null 2>&1; then
                            echo "✅ IP Dashboard API ($DASHBOARD_HOST_RAW) berhasil dijangkau."
                            PROTOCOL="https://" # Default HTTPS untuk IP
                            BASE_URL="${PROTOCOL}${DASHBOARD_HOST_RAW}"
                            DASHBOARD_MONITORING_IP=$DASHBOARD_HOST_RAW # Simpan IP untuk SNMP
                            ip_valid=1
                        else
                            echo "⛔ Gagal melakukan ping ke $DASHBOARD_HOST_RAW. Pastikan IP benar dan server up."
                        fi
                    else
                        echo "⛔ Format IP tidak valid. Mohon masukkan IP dengan format yang benar."
                    fi
                done
                url_type_valid=1
                ;;
            2)
                local domain_valid=0
                while [ $domain_valid -eq 0 ]; do
                    read -p "🌐 Masukkan Nama Domain Dashboard API (contoh: dashboard.example.com atau https://dashboard.example.com): " DASHBOARD_HOST_RAW
                    if [[ -z "$DASHBOARD_HOST_RAW" ]]; then
                        echo "⛔ Nama domain tidak boleh kosong."
                    else
                        # Periksa protokol yang sudah ada
                        if [[ "$DASHBOARD_HOST_RAW" =~ ^(http|https):// ]]; then
                            PROTOCOL=$(echo "$DASHBOARD_HOST_RAW" | grep -oE '^(http|https)://')
                            # Hapus protokol untuk validasi dan penanganan selanjutnya
                            DASHBOARD_HOST_CLEAN=${DASHBOARD_HOST_RAW#*//}
                        else
                            PROTOCOL="https://" # Default ke HTTPS jika tidak ada protokol yang diberikan
                            DASHBOARD_HOST_CLEAN=$DASHBOARD_HOST_RAW
                        fi

                        # Validasi domain dasar (bisa lebih kuat jika diperlukan)
                        # Hapus port atau '/api' jika sudah ada untuk validasi domain murni
                        local temp_host_for_validation=${DASHBOARD_HOST_CLEAN}
                        temp_host_for_validation=${temp_host_for_validation%:*} # Hapus port jika ada
                        temp_host_for_validation=${temp_host_for_validation%/api*} # Hapus /api jika ada

                        if [[ "$temp_host_for_validation" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$ ]]; then
                            echo "✅ Nama Domain ($DASHBOARD_HOST_CLEAN) diterima."
                            BASE_URL="${PROTOCOL}${DASHBOARD_HOST_CLEAN}" # Bangun BASE_URL dengan protokol yang benar
                            domain_valid=1
                        else
                            echo "⛔ Format domain tidak valid. Mohon masukkan domain dengan format yang benar."
                        fi
                    fi
                done
                url_type_valid=1
                ;;
            *)
                echo "⛔ Pilihan tidak valid. Silakan masukkan 1 atau 2."
                ;;
        esac
    done

    # Tanya tentang port kustom (berlaku untuk IP dan Domain)
    read -p "Apakah Dashboard API menggunakan port kustom (contoh: 3000)? [y/N]: " USE_CUSTOM_PORT
    USE_CUSTOM_PORT=${USE_CUSTOM_PORT:-N}

    local FINAL_PORT_PART=""
    if [[ "$USE_CUSTOM_PORT" =~ ^[yY]$ ]]; then
        local port_valid=0
        while [ $port_valid -eq 0 ]; do
            read -p "🔌 Masukkan Port Kustom (contoh: 3000): " DASHBOARD_PORT
            if [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] && [ "$DASHBOARD_PORT" -ge 1 ] && [ "$DASHBOARD_PORT" -le 65535 ]; then
                FINAL_PORT_PART=":${DASHBOARD_PORT}"
                port_valid=1
            else
                echo "⛔ Port tidak valid. Masukkan angka antara 1 dan 65535."
            fi
        done
    fi

    # Bangun DASHBOARD_API_URL akhir
    # Pastikan tidak ada `/api` ganda jika user sudah memasukkannya
    local TEMP_DASHBOARD_API_URL="${BASE_URL}${FINAL_PORT_PART}"
    if [[ "$TEMP_DASHBOARD_API_URL" != */api ]]; then
        DASHBOARD_API_URL="${TEMP_DASHBOARD_API_URL}/api"
    else
        DASHBOARD_API_URL="${TEMP_DASHBOARD_API_URL}"
    fi

    echo "✅ URL Dashboard API akan diatur ke: $DASHBOARD_API_URL"

    echo ""
    while [ -z "$SERVER_ID" ]; do
        read -p "🏷️ Masukkan ID Server (contoh: SERVER-01): " SERVER_ID
        if [ -z "$SERVER_ID" ]; then
            echo "⛔ ID Server tidak boleh kosong."
        fi
    done

    echo ""
    local default_ovpn_dir="/home/$SUDO_USER/ovpn"
    read -p "📁 Masukkan direktori untuk file OVPN (default: $default_ovpn_dir): " OVPN_DIR_INPUT
    OVPN_DIR=${OVPN_DIR_INPUT:-$default_ovpn_dir}
    echo "✅ Direktori OVPN: $OVPN_DIR"
}

# --- FUNGSI BARU: Input SNMP ---
get_snmp_input() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "🛡️  KONFIGURASI SNMP MONITORING"
    echo "═══════════════════════════════════════════════"
    echo ""
    read -p "🔧 Apakah Anda ingin mengkonfigurasi SNMP untuk monitoring? [Y/n]: " CONFIGURE_SNMP
    CONFIGURE_SNMP=${CONFIGURE_SNMP:-Y}

    if [[ "$CONFIGURE_SNMP" =~ ^[yY]$ ]]; then
        echo ""
        echo "ℹ️  SNMP memungkinkan dashboard untuk memonitor CPU, RAM, dan metrik sistem lainnya."
        echo ""
        
        while [ -z "$SNMP_COMMUNITY_STRING" ]; do
            read -p "🔒 Masukkan SNMP Community String (seperti password, contoh: public_vpn): " SNMP_COMMUNITY_STRING
            if [ -z "$SNMP_COMMUNITY_STRING" ]; then
                echo "⛔ Community string tidak boleh kosong."
            fi
        done
        
        # Jika dashboard menggunakan domain, kita perlu IP-nya untuk SNMP
        if [ -z "$DASHBOARD_MONITORING_IP" ]; then
            echo ""
            echo "⚠️  Untuk keamanan SNMP, kita perlu mengizinkan hanya IP tertentu untuk mengakses."
            while [ -z "$DASHBOARD_MONITORING_IP" ]; do
                read -p "🌍 Masukkan Alamat IP dari server Dashboard untuk diizinkan memonitor: " DASHBOARD_MONITORING_IP
                if [[ ! $DASHBOARD_MONITORING_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    echo "⛔ Format IP tidak valid. Mohon masukkan IP dengan format yang benar."
                    DASHBOARD_MONITORING_IP=""
                fi
            done
        fi
        
        echo ""
        echo "✅ SNMP akan dikonfigurasi dengan:"
        echo "   • Community String: $SNMP_COMMUNITY_STRING"
        echo "   • IP yang diizinkan: $DASHBOARD_MONITORING_IP"
        echo ""
    else
        echo "ℹ️  Melewati konfigurasi SNMP."
        echo ""
    fi
}

# Temukan jalur Easy-RSA index.txt secara dinamis
find_easy_rsa_path() {
    echo "🔍 Mencari jalur Easy-RSA index.txt secara dinamis..."
    local paths_to_check=(
        "/etc/openvpn/easy-rsa/pki/index.txt"
        "/etc/openvpn/pki/index.txt"
        "/usr/share/easy-rsa/pki/index.txt"
        "/etc/easy-rsa/pki/index.txt"
    )
    for path in "${paths_to_check[@]}"; do
        if [ -f "$path" ]; then
            EASY_RSA_INDEX_PATH="$path"
            EASY_RSA_DIR=$(dirname "$EASY_RSA_INDEX_PATH" | xargs dirname)
            EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_DIR/SERVER_NAME_GENERATED"
            echo "✅ Ditemukan jalur index.txt: $EASY_RSA_INDEX_PATH"
            return 0
        fi
    done
    echo "⛔ Jalur Easy-RSA index.txt tidak ditemukan di lokasi umum. Deployment gagal."
    echo "   Lokasi yang diperiksa:"
    for path in "${paths_to_check[@]}"; do
        echo "   • $path"
    done
    return 1
}

# Periksa apakah layanan OpenVPN sedang berjalan
check_openvpn_service() {
    echo "🔎 Mencari layanan OpenVPN yang sedang berjalan..."
    local service_names=("openvpn-server@server" "openvpn@server" "openvpn")
    for service in "${service_names[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo "✅ Layanan OpenVPN ($service) ditemukan dan berjalan."
            return 0
        fi
    done
    if pgrep openvpn > /dev/null; then
        echo "✅ Proses OpenVPN ditemukan, tapi layanan tidak terdaftar secara resmi."
        return 0
    fi
    echo "⛔ Layanan atau proses OpenVPN tidak ditemukan. Deployment dibatalkan."
    echo "   Pastikan OpenVPN sudah terinstal dan berjalan, atau letakkan skrip instalasi di:"
    echo "   $OPENVPN_INSTALL_SCRIPT_PATH"
    return 1
}

# Instal dependensi sistem, Node.js, dan Python
install_dependencies() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "⚙️  MENGINSTAL DEPENDENSI SISTEM"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📦 Memperbarui daftar paket..."
    apt-get update -qq

    echo "📦 Menginstal dependensi sistem..."
    # PERBAIKAN: Tambahkan snmpd untuk SNMP monitoring, hapus psutil karena tidak dibutuhkan
    apt-get install -y openvpn python3 python3-pip python3-venv expect curl dos2unix at snmpd
    # FIX BUG: Install sudo, jika belum terinstall, agar 'sudo -u' bisa digunakan
    apt-get install -y sudo

    # Perbaiki line endings script ini
    dos2unix "$0" >/dev/null 2>&1

    echo ""
    echo "⚙️  Menginstal Node.js secara manual..."
    if ! command -v node &> /dev/null; then
        echo "📥 Node.js tidak ditemukan. Menginstal Node.js $NODE_VERSION..."
        
        # Download dengan progress bar
        echo "⬇️  Mengunduh Node.js..."
        curl -# -o /tmp/"$NODE_DIR".tar.gz "$NODE_URL"
        
        echo "📂 Mengekstrak Node.js..."
        tar -xzf /tmp/"$NODE_DIR".tar.gz -C /tmp/
        mkdir -p /usr/local/lib/nodejs
        cp -Rv /tmp/"$NODE_DIR" /usr/local/lib/nodejs/ >/dev/null

        # Buat symlink
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/node /usr/bin/node
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/npm /usr/bin/npm
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/npx /usr/bin/npx

        echo "✅ Verifikasi instalasi Node.js..."
        node_version=$(node -v)
        echo "   Node.js version: $node_version"
        echo "✅ Node.js terinstal dengan sukses."
    else
        current_node_version=$(node -v)
        echo "☑️  Node.js sudah terinstal (versi: $current_node_version). Melewati."
    fi

    echo ""
    echo "⚙️  Menginstal PM2..."
    # FIX BUG: Install PM2 sebagai user root
    if ! command -v pm2 &> /dev/null; then
        npm install -g pm2 >/dev/null 2>&1
        echo "✅ PM2 berhasil diinstal secara global."
    else
        pm2_version=$(pm2 --version)
        echo "☑️  PM2 sudah terinstal (versi: $pm2_version). Melewati."
    fi

    echo ""
    echo "═══════════════════════════════════════════════"
    echo "🐍 MENGKONFIGURASI PYTHON VIRTUAL ENVIRONMENT"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "🏗️  Membuat Python virtual environment di $VENV_PATH..."
    # Buat venv sebagai SUDO_USER untuk memastikan kepemilikan yang benar
    if sudo -u "$SUDO_USER" python3 -m venv "$VENV_PATH"; then
        echo "✅ Virtual environment berhasil dibuat."
    else
        echo "⛔ Gagal membuat virtual environment. Periksa instalasi Python3."
        exit 1
    fi

    echo "📦 Menginstal dependensi Python di dalam venv..."
    # Jalankan pip dari dalam venv untuk menginstal paket secara lokal
    if sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install --upgrade pip --quiet; then
        echo "✅ pip berhasil diperbarui."
    else
        echo "⛔ Gagal memperbarui pip."
        exit 1
    fi
    
    # PERBAIKAN: Hapus psutil karena kita menggunakan SNMP
    echo "   Menginstal: fastapi, uvicorn, pydantic, python-dotenv, requests, aiohttp..."
    if sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install fastapi "uvicorn[standard]" pydantic python-dotenv requests aiohttp --quiet; then
        echo "✅ Semua dependensi Python berhasil diinstal di dalam virtual environment."
    else
        echo "⛔ Gagal menginstal dependensi Python."
        exit 1
    fi
    
    echo ""
    echo "✅ INSTALASI DEPENDENSI SELESAI"
}

# --- FUNGSI BARU: Konfigurasi SNMP ---
configure_snmp() {
    if [[ "$CONFIGURE_SNMP" =~ ^[yY]$ ]]; then
        echo ""
        echo "═══════════════════════════════════════════════"
        echo "🛡️  MENGKONFIGURASI SNMP DAEMON"
        echo "═══════════════════════════════════════════════"
        echo ""
        
        echo "📝 Membuat konfigurasi SNMP..."
        # Buat backup konfigurasi lama jika ada
        if [ -f /etc/snmp/snmpd.conf ]; then
            cp /etc/snmp/snmpd.conf /etc/snmp/snmpd.conf.backup.$(date +%Y%m%d_%H%M%S)
            echo "   Backup konfigurasi lama dibuat."
        fi
        
        # Buat file konfigurasi yang aman
        cat << EOF | tee /etc/snmp/snmpd.conf > /dev/null
#
# Konfigurasi SNMP untuk OpenVPN Agent Monitoring
# Generated by deploymentovpn.sh
#

# Izinkan akses read-only dari IP dashboard
rocommunity $SNMP_COMMUNITY_STRING $DASHBOARD_MONITORING_IP

# Informasi sistem
sysLocation    "OpenVPN Server - Managed by VPN Agent"
sysContact     "OpenVPN Agent <agent@vpnserver.local>"
sysName        "$SERVER_ID"

# Disable default public community untuk keamanan
com2sec notConfigUser  default       public

# Konfigurasi akses grup
group   notConfigGroup v1           notConfigUser
group   notConfigGroup v2c          notConfigUser

# View yang dibatasi
view    systemview    included   .1.3.6.1.2.1.1
view    systemview    included   .1.3.6.1.2.1.25.1.1

# Akses terbatas
access  notConfigGroup ""      any       noauth    exact  systemview none none

# Nonaktifkan akses tidak diperlukan
dontLogTCPWrappersConnects yes
EOF

        echo "🔄 Merestart dan mengaktifkan layanan SNMP..."
        if systemctl restart snmpd && systemctl enable snmpd; then
            echo "✅ SNMP daemon berhasil dikonfigurasi dan diaktifkan."
            echo ""
            echo "📊 Informasi SNMP:"
            echo "   • Community String: $SNMP_COMMUNITY_STRING"
            echo "   • IP yang diizinkan: $DASHBOARD_MONITORING_IP"
            echo "   • Port: 161 (UDP)"
            echo ""
            
            # Test SNMP secara lokal
            echo "🧪 Testing SNMP secara lokal..."
            if command -v snmpget &> /dev/null; then
                if snmpget -v2c -c "$SNMP_COMMUNITY_STRING" localhost 1.3.6.1.2.1.1.1.0 >/dev/null 2>&1; then
                    echo "✅ SNMP test berhasil."
                else
                    echo "⚠️  SNMP test gagal, tapi konfigurasi sudah dibuat."
                fi
            else
                echo "ℹ️  snmp-utils belum terinstal, tidak dapat melakukan test lokal."
            fi
        else
            echo "⛔ Gagal mengkonfigurasi SNMP daemon."
            exit 1
        fi
        
        echo "✅ KONFIGURASI SNMP SELESAI"
    else
        echo ""
        echo "ℹ️  Melewati konfigurasi SNMP."
    fi
}

# Buat file .env dari input user
create_env_file() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "📄 MEMBUAT FILE KONFIGURASI"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📝 Membuat file .env dengan konfigurasi..."
    # Gunakan tee untuk membuat file .env dengan izin sudo
    cat << EOF | tee "$SCRIPT_DIR/.env" > /dev/null
# OpenVPN Agent Configuration
# Generated by deploymentovpn.sh on $(date)

# API Configuration
AGENT_API_KEY="$AGENT_API_KEY"
SERVER_ID="$SERVER_ID"
DASHBOARD_API_URL="$DASHBOARD_API_URL"

# Script Paths
SCRIPT_PATH="$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
OVPN_DIR="$OVPN_DIR"

# Easy-RSA Configuration
EASY_RSA_INDEX_PATH="$EASY_RSA_INDEX_PATH"
EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_SERVER_NAME_PATH"

# Logging
OVPN_ACTIVITY_LOG_PATH="/var/log/openvpn/user_activity.log"

# PM2 Configuration
PM2_APP_NAME="$APP_NAME"
EOF
    
    # Set ownership ke SUDO_USER
    chown "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/.env"
    chmod 600 "$SCRIPT_DIR/.env"
    
    echo "✅ File .env berhasil dibuat dengan konfigurasi lengkap."
    echo "   Lokasi: $SCRIPT_DIR/.env"
}

# Deploy skrip Python dan Bash
deploy_scripts() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "📂 MENYEBARKAN SKRIP APLIKASI"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📁 Memastikan struktur direktori..."
    # Direktori sudah dibuat sebelumnya, hanya memastikan ada folder logs
    mkdir -p "$SCRIPT_DIR/logs"
    chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR"

    # Simpan skrip agen Python (menggunakan versi terbaik dari original)
    echo "🐍 Menulis skrip agen Python ke $SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME..."
    # Gunakan sudo tee untuk menulis file sebagai SUDO_USER
    cat << '_PYTHON_SCRIPT_EOF_' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME" > /dev/null
# main.py (OpenVPN Agent - Final Version)

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from subprocess import run, PIPE, CalledProcessError
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import subprocess
import os
import re
import requests
import asyncio
from datetime import datetime, timezone
import hashlib
import sys
from typing import List, Optional
import shlex

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(SCRIPT_DIR, '.env'))

app = FastAPI()

# Env config
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
SERVER_ID = os.getenv("SERVER_ID")
DASHBOARD_API_URL = os.getenv("DASHBOARD_API_URL")
SCRIPT_PATH = os.getenv("SCRIPT_PATH", "./openvpn-client-manager.sh")
OVPN_DIR = os.getenv("OVPN_DIR", "/home/ovpn")
EASY_RSA_INDEX_PATH = os.getenv("EASY_RSA_INDEX_PATH", "/etc/openvpn/easy-rsa/pki/index.txt")
EASY_RSA_SERVER_NAME_PATH = os.getenv("EASY_RSA_SERVER_NAME_PATH", "/etc/openvpn/easy-rsa/SERVER_NAME_GENERATED")
OVPN_ACTIVITY_LOG_PATH = os.getenv("OVPN_ACTIVITY_LOG_PATH", "/var/log/openvpn/user_activity.log")
PM2_APP_NAME = os.getenv("PM2_APP_NAME")

if not AGENT_API_KEY:
    raise RuntimeError("Missing AGENT_API_KEY in .env")
if not SERVER_ID:
    raise RuntimeError("Missing SERVER_ID in .env")
if not DASHBOARD_API_URL:
    raise RuntimeError("Missing DASHBOARD_API_URL in .env")
# FIX BUG: Tidak perlu cek file di sini, karena akan diakses dengan sudo
# if not os.path.exists(EASY_RSA_INDEX_PATH):
#     raise RuntimeError(f"Easy-RSA index.txt not found at {EASY_RSA_INDEX_PATH}")

# Global variables to store the last sent checksums
last_vpn_profiles_checksum = None
last_activity_log_checksum = None

# --- Middleware for auth ---
@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    if request.url.path not in ["/health", "/stats"]:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer ") or auth.split(" ")[1] != AGENT_API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)

# --- Utility Functions ---
def sanitize_username(username: str) -> str:
    stripped_username = username.strip()
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '', stripped_username).lower()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,30}$", sanitized):
        raise ValueError("Invalid username format")
    return sanitized

def get_openvpn_service_status() -> str:
    # FIX BUG: Cek status service dengan sudo
    try:
        result = run(["sudo", "systemctl", "is-active", "openvpn@server"], stdout=PIPE, stderr=PIPE, text=True)
        if result.stdout.strip() == "active":
            return "running"
        elif result.stdout.strip() == "inactive":
            return "stopped"
        else:
            return "error"
    except Exception as e:
        print(f"Error checking OpenVPN service status: {e}")
        return "error"

def get_server_cn() -> str:
    # FIX BUG: Jalankan sebagai root, jadi tidak perlu sudo
    try:
        if os.path.exists(EASY_RSA_SERVER_NAME_PATH):
            with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"Error reading server CN file: {e}")
    return "server_irL5Kfmg3FnRZaGE"

def parse_index_txt() -> tuple[list[dict], str]:
    profiles = []
    # FIX BUG: Jalankan sebagai root, jadi tidak perlu sudo
    try:
        with open(EASY_RSA_INDEX_PATH, 'r') as f:
            raw_content = f.read()
            checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()
            server_cn = get_server_cn()
            for line in raw_content.strip().split('\n'):
                parts = line.strip().split('\t')
                if len(parts) >= 6:
                    cert_status = parts[0]
                    expiration_date_str = parts[1]
                    expiration_date = None
                    if expiration_date_str and expiration_date_str != 'Z':
                        try:
                            match = re.match(r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', expiration_date_str)
                            if match:
                                year, month, day, hour, minute, second = match.groups()
                                full_year = int(year) + 2000 if int(year) < 70 else int(year) + 1900
                                iso_format_str = f"{full_year}-{month}-{day}T{hour}:{minute}:{second}Z"
                                expiration_date = datetime.strptime(iso_format_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        except ValueError:
                            expiration_date = None
                    revocation_date = None
                    if cert_status == 'R' and len(parts) >= 3 and parts[2] and parts[2] != 'Z':
                        revocation_date_str = parts[2]
                        try:
                            match = re.match(r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', revocation_date_str)
                            if match:
                                year, month, day, hour, minute, second = match.groups()
                                full_year = int(year) + 2000 if int(year) < 70 else int(year) + 1900
                                iso_format_str = f"{full_year}-{month}-{day}T{hour}:{minute}:{second}Z"
                                revocation_date = datetime.strptime(iso_format_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        except ValueError:
                            revocation_date = None
                    serial_number = parts[3]
                    cn_match = re.search(r'/CN=([^/]+)', line)
                    username_raw = cn_match.group(1) if cn_match else "unknown"
                    username = "".join(filter(str.isprintable, username_raw)).lower().strip()
                    if username_raw == server_cn:
                        continue
                    vpn_cert_status = "UNKNOWN"
                    if cert_status == 'V': vpn_cert_status = "VALID"
                    elif cert_status == 'R': vpn_cert_status = "REVOKED"
                    elif cert_status == 'E': vpn_cert_status = "EXPIRED"
                    ovpn_file_content = None
                    if vpn_cert_status == "VALID":
                        ovpn_file_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        try:
                            # FIX BUG: Jalankan sebagai root, jadi tidak perlu sudo
                            if os.path.exists(ovpn_file_path):
                                with open(ovpn_file_path, 'r') as ovpn_f:
                                    ovpn_file_content = ovpn_f.read()
                        except Exception as e:
                            print(f"Warning: Could not read OVPN file for {username}. Error: {e}")
                    profiles.append({
                        "username": username,
                        "status": vpn_cert_status,
                        "expirationDate": expiration_date.isoformat() if expiration_date else None,
                        "revocationDate": revocation_date.isoformat() if revocation_date else None,
                        "serialNumber": serial_number,
                        "ovpnFileContent": ovpn_file_content,
                    })
            return profiles, checksum
    except Exception as e:
        print(f"Error parsing index.txt or calculating checksum: {e}")
        return [], ""

def get_openvpn_active_users_from_status_log() -> list[str]:
    active_users = []
    status_log_path = "/var/log/openvpn/status.log"
    # FIX BUG: Jalankan sebagai root, jadi tidak perlu sudo
    if not os.path.exists(status_log_path):
        return []
    try:
        with open(status_log_path, 'r') as f:
            content = f.read()
            start_parsing = False
            for line in content.strip().split('\n'):
                if line.startswith("Common Name,Real Address"):
                    start_parsing = True
                    continue
                if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                    break
                if start_parsing and line:
                    parts = line.split(',')
                    if len(parts) >= 1:
                        username = parts[0].lower()
                        if username:
                            active_users.append(username)
        return active_users
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

def parse_activity_logs() -> tuple[list[dict], str]:
    logs = []
    raw_content = ""
    log_files_to_check = [OVPN_ACTIVITY_LOG_PATH, f"{OVPN_ACTIVITY_LOG_PATH}.1"]

    for log_file in log_files_to_check:
        if os.path.exists(log_file):
            try:
                # FIX BUG: Jalankan sebagai root, jadi tidak perlu sudo
                with open(log_file, 'r') as f:
                    raw_content += f.read()
            except Exception as e:
                print(f"Warning: Could not read activity log {log_file}: {e}")

    if not raw_content:
        return [], ""

    checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()

    for line in raw_content.strip().split('\n'):
        parts = line.strip().split(',')
        if len(parts) < 2:
            continue

        try:
            timestamp = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S').isoformat() + "Z"

            log_entry = {
                "timestamp": timestamp,
                "action": parts[1],
                "username": parts[2] if len(parts) > 2 and parts[2] else None,
                "publicIp": parts[3] if len(parts) > 3 and parts[3] else None,
                "vpnIp": parts[4] if len(parts) > 4 and parts[4] else None,
                "bytesReceived": int(parts[5]) if len(parts) > 5 and parts[1] == "DISCONNECT" else None,
                "bytesSent": int(parts[6]) if len(parts) > 6 and parts[1] == "DISCONNECT" else None,
            }
            logs.append(log_entry)
        except (ValueError, IndexError) as e:
            print(f"Warning: Skipping malformed log line: '{line}'. Error: {e}")
            continue

    return logs, checksum

# --- Models ---
class CreateUserRequest(BaseModel):
    username: str

class EnhancedServerStatusReport(BaseModel):
    serverId: str
    serviceStatus: str
    activeUsers: list[str]

class VpnUserProfileData(BaseModel):
    username: str
    status: str
    expirationDate: Optional[str] = None
    revocationDate: Optional[str] = None
    serialNumber: Optional[str] = None
    ovpnFileContent: Optional[str] = None

class UserActivityLogEntry(BaseModel):
    timestamp: str
    action: str
    username: Optional[str] = None
    publicIp: Optional[str] = None
    vpnIp: Optional[str] = None
    bytesReceived: Optional[int] = None
    bytesSent: Optional[int] = None

class ActionLogEntry(BaseModel):
    id: str
    action: str
    vpnUserId: Optional[str] = None
    details: Optional[str] = None

# --- Background Task ---
async def background_task_loop():
    global last_vpn_profiles_checksum
    global last_activity_log_checksum

    while True:
        try:
            headers = {"Authorization": f"Bearer {AGENT_API_KEY}"}

            # 1. Report Node Metrics (hanya service status, CPU/RAM via SNMP)
            service_status = get_openvpn_service_status()
            active_users = get_openvpn_active_users_from_status_log()
            node_metrics_payload = {
                "serverId": SERVER_ID,
                "serviceStatus": service_status,
                "activeUsers": active_users
            }
            await asyncio.to_thread(
                requests.post, f"{DASHBOARD_API_URL}/agent/report-status", json=node_metrics_payload, headers=headers, timeout=10
            )
            print(f"Sent status report for server {SERVER_ID}")

            # 2. Sync VPN Profiles (on change)
            current_profiles, current_profiles_checksum = parse_index_txt()
            if current_profiles_checksum != last_vpn_profiles_checksum:
                vpn_profiles_payload = {"serverId": SERVER_ID, "vpnProfiles": current_profiles}
                await asyncio.to_thread(
                    requests.post, f"{DASHBOARD_API_URL}/agent/sync-profiles", json=vpn_profiles_payload, headers=headers, timeout=10
                )
                print(f"Sent VPN profiles sync for server {SERVER_ID} (checksum changed).")
                last_vpn_profiles_checksum = current_profiles_checksum
            else:
                print(f"VPN profiles checksum unchanged for server {SERVER_ID}. Skipping sync.")

            # 3. Sync User Activity Logs (on change)
            current_activity_logs, current_activity_checksum = parse_activity_logs()
            if current_activity_checksum and current_activity_checksum != last_activity_log_checksum:
                activity_logs_payload = {
                    "serverId": SERVER_ID,
                    "activityLogs": current_activity_logs
                }
                await asyncio.to_thread(
                    requests.post, f"{DASHBOARD_API_URL}/agent/report-activity-logs", json=activity_logs_payload, headers=headers, timeout=10
                )
                print(f"Sent user activity logs for server {SERVER_ID} (checksum changed).")
                last_activity_log_checksum = current_activity_checksum
            else:
                print(f"User activity log checksum unchanged for server {SERVER_ID}. Skipping sync.")

            # 4. Process Pending Actions from Dashboard
            action_logs_response = await asyncio.to_thread(
                requests.get, f"{DASHBOARD_API_URL}/agent/action-logs?serverId={SERVER_ID}", headers=headers, timeout=10
            )
            action_logs_response.raise_for_status()
            pending_actions = action_logs_response.json()

            for action_log in pending_actions:
                try:
                    log_entry = ActionLogEntry(**action_log)
                    print(f"Processing action log: {log_entry.id} - {log_entry.action}")
                    execution_result = {"status": "success", "message": "", "ovpnFileContent": None}
                    
                    # Jalankan script manager dengan sudo karena butuh hak akses root
                    if log_entry.action == "CREATE_USER":
                        username = sanitize_username(log_entry.details)
                        run(["sudo", SCRIPT_PATH, "create", username], check=True)
                        ovpn_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        # Baca file OVPN tanpa sudo karena dijalankan sebagai root
                        result_ovpn = run(["cat", ovpn_path], capture_output=True, text=True, check=True)
                        execution_result["ovpnFileContent"] = result_ovpn.stdout
                        execution_result["message"] = f"User {username} created."
                    elif log_entry.action in ["REVOKE_USER", "DELETE_USER"]:
                        username = sanitize_username(log_entry.details)
                        run(["sudo", SCRIPT_PATH, "revoke", username], check=True)
                        execution_result["message"] = f"User {username} revoked."
                    elif log_entry.action == "DECOMMISSION_AGENT":
                        try:
                            print(f"Sending decommission confirmation for {SERVER_ID}...")
                            requests.post(
                                f"{DASHBOARD_API_URL}/agent/decommission-complete",
                                json={"serverId": SERVER_ID},
                                headers=headers,
                                timeout=5
                            )
                            print("Decommission signal sent.")
                        
                        except Exception as e:
                            print(f"Could not send decommission signal: {e}")

                        finally:
                            print("Scheduling self-destruct script...")
                            app_name = PM2_APP_NAME or SERVER_ID
                            script = f"sleep 10 && sudo /bin/bash {SCRIPT_DIR}/self-destruct.sh {app_name}"

                            # Biarkan shell yang handle redirect dan background
                            subprocess.Popen(
                                f"nohup sh -c \"{script}\" >/dev/null 2>&1 &",
                                shell=True
                            )

                            sys.exit(0)

                    if log_entry.action != "DECOMMISSION_AGENT":
                        await asyncio.to_thread(
                            requests.post, f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                            json={"actionLogId": log_entry.id, "status": execution_result["status"], "message": execution_result["message"], "ovpnFileContent": execution_result["ovpnFileContent"]},
                            headers=headers,
                            timeout=10
                        )
                except Exception as e:
                    print(f"Error processing action log {action_log.get('id', 'N/A')}: {e}")
                    await asyncio.to_thread(
                        requests.post, f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                        json={"actionLogId": action_log.get('id', 'N/A'), "status": "failed", "message": f"Agent internal error: {e}"},
                        headers=headers,
                        timeout=10
                    )

        except requests.exceptions.RequestException as e:
            print(f"Error communicating with dashboard API: {e}")
        except Exception as e:
            print(f"An unexpected error occurred in background task: {e}")

        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(background_task_loop())

# --- Agent Endpoints ---
@app.get("/health")
def health(): return {"status": "ok"}

@app.get("/stats")
def get_stats():
    return {"serviceStatus": get_openvpn_service_status()}

@app.get("/profiles")
def list_profiles_agent_side():
    profiles, _ = parse_index_txt()
    return profiles

@app.get("/active-users")
def list_active_users_agent_side():
    return {"activeUsers": get_openvpn_active_users_from_status_log()}

@app.post("/users")
async def create_user_direct(data: CreateUserRequest):
    username = sanitize_username(data.username)
    # Jalankan script manager dengan sudo
    result = run(["sudo", SCRIPT_PATH, "create", username], stdout=PIPE, stderr=PIPE, text=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"username": username, "message": "User created."}

@app.delete("/users/{username}")
def revoke_user_direct(username: str):
    username = sanitize_username(username)
    # Jalankan script manager dengan sudo
    result = run(["sudo", SCRIPT_PATH, "revoke", username], stdout=PIPE, stderr=PIPE, text=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"detail": f"User {username} revoked"}

_PYTHON_SCRIPT_EOF_
    chmod +x "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME"
    chown "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME"
    echo "✅ Skrip agen Python berhasil di-deploy."

    # Simpan skrip manajer klien (menggunakan versi terbaik dari original)
    echo "⚙️  Menulis skrip manajer klien ke $SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME..."
    cat << 'CLIENT_MANAGER_EOF' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME" > /dev/null
#!/bin/bash
# shellcheck disable=SC2164,SC2034

# Path ke skrip install OpenVPN (pastikan sesuai)
OPENVPN_INSTALL_SCRIPT="/root/ubuntu-22.04-lts-vpn-server.sh"

create_client() {
    local username=$1
    if [ -z "$username" ]; then
        echo "⛔ Bro masukkan username. Usage: $0 create <username>"
        exit 1
    fi

    echo "➕ Creating new client: $username"
    # MODIFIKASI: Jalankan script instalasi OpenVPN dengan sudo
    printf "1\n%s\n1\n" "$username" | sudo "$OPENVPN_INSTALL_SCRIPT"
    echo "✅ Client '$username' created successfully."
}

revoke_client() {
    local username="$1"

    if [ -z "$username" ]; then
        echo "⛔ Bro masukkan username. Usage: $0 revoke <username>"
        exit 1
    fi

    echo "🔍 Nyari nomor client '$username' dari index.txt..."

    # Ambil nomor client dari index.txt (valid client only, case-insensitive)
    # FIX BUG: Gunakan sudo untuk membaca file index.txt
    local client_number
    client_number=$(sudo tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f2 | nl -w1 -s' ' | \
        awk -v name="$username" 'BEGIN{IGNORECASE=1} $2 == name {print $1; exit}')


    if [ -z "$client_number" ]; then
        echo "⛔ Gak nemu client '$username'. Coba cek list pake: ./openvpn-client-manager.sh list"
        exit 1
    fi

    echo "✅ Ketemu! '$username' ada di nomor $client_number"
    echo "⚙️  Kirim input ke script buat revoke..."

    expect <<EOF
        spawn sudo "$OPENVPN_INSTALL_SCRIPT"
        expect "Select an option*" { send "2\r" }
        expect "Select one client*" { send "$client_number\r" }
        expect eof
EOF

    echo "✅ Client '$username' udah direvoke. RIP 🪦"
}

list_clients() {
    echo "📋 Listing active clients dari Easy-RSA index.txt..."
    # FIX BUG: Gunakan sudo untuk membaca file index.txt
    if [[ -f /etc/openvpn/easy-rsa/pki/index.txt ]]; then
        sudo grep "^V" /etc/openvpn/easy-rsa/pki/index.txt | \
        cut -d '=' -f2 | \
        grep -v '^server_' # Adjust this line if needed
    else
        echo "⛔ index.txt gak ketemu di /etc/openvpn/easy-rsa/pki/"
        exit 1
    fi
}

# Main entrypoint
case "$1" in
    create)
        create_client "$2"
        ;;
    revoke)
        revoke_client "$2"
        ;;
    list)
        list_clients
        ;;
    *)
        echo "Usage: $0 {create|revoke|list} <username>"
        exit 1
        ;;
esac
CLIENT_MANAGER_EOF
    chmod +x "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
    chown "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
    echo "✅ Skrip manajer klien berhasil di-deploy."

    echo "🗑️  Menulis skrip penghapusan mandiri (self-destruct)..."
    cat << 'SELF_DESTRUCT_EOF' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/self-destruct.sh" > /dev/null
#!/bin/bash
# self-destruct.sh (Final & Robust Version)
set -e

if [ "$EUID" -ne 0 ]; then
    echo "⛔ Skrip ini harus dijalankan dengan sudo."
    exit 1
fi

PM2_APP_NAME="$1"
AGENT_DIR=$(dirname "$(readlink -f "$0")")

echo "🛑 Menerima perintah penghapusan mandiri untuk '$PM2_APP_NAME'..."

echo "[-] Menghentikan dan menghapus proses PM2: $PM2_APP_NAME"
# FIX BUG: Jalankan PM2 sebagai root
pm2 stop "$PM2_APP_NAME" || true
pm2 delete "$PM2_APP_NAME" || true
pm2 save --force

echo "🗑️ Menghapus direktori instalasi agen: $AGENT_DIR"
# FIX BUG: Gunakan sudo -u untuk menghapus file
rm -rf "$AGENT_DIR"

echo "✅ Proses penghapusan mandiri agen selesai."
SELF_DESTRUCT_EOF

    chmod +x "$SCRIPT_DIR/self-destruct.sh"
    chown "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/self-destruct.sh"
    echo "✅ Skrip penghapusan mandiri berhasil di-deploy."
    
    echo ""
    echo "✅ SEMUA SKRIP BERHASIL DI-DEPLOY"
}

# Buat file konfigurasi PM2 berdasarkan input user
create_pm2_ecosystem_file() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "🚀 MEMBUAT KONFIGURASI PM2"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📝 Membuat file ecosystem.config.js..."
    # Gunakan tee untuk membuat file dengan hak akses root
    cat << EOF | tee "$SCRIPT_DIR/ecosystem.config.js" > /dev/null
module.exports = {
  apps: [{
    name: "$APP_NAME",
    script: "$VENV_PATH/bin/python",
    args: "-m uvicorn main:app --host 0.0.0.0 --port 8080",
    cwd: "$SCRIPT_DIR",
    exec_mode: "fork",
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "production",
      AGENT_API_KEY: "$AGENT_API_KEY",
      SERVER_ID: "$SERVER_ID",
      PM2_APP_NAME: "$APP_NAME",
      DASHBOARD_API_URL: "$DASHBOARD_API_URL",
      SCRIPT_PATH: "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME",
      OVPN_DIR: "$OVPN_DIR",
      EASY_RSA_INDEX_PATH: "$EASY_RSA_INDEX_PATH",
      EASY_RSA_SERVER_NAME_PATH: "$EASY_RSA_SERVER_NAME_PATH",
      OVPN_ACTIVITY_LOG_PATH: "/var/log/openvpn/user_activity.log"
    },
    output: "$SCRIPT_DIR/logs/agent-out.log",
    error: "$SCRIPT_DIR/logs/agent-err.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }]
};
EOF
    chown "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/ecosystem.config.js"
    echo "✅ File ecosystem.config.js berhasil dibuat."
}

# Konfigurasi PM2 untuk menjalankan agen Python
configure_pm2() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "🚀 MENGKONFIGURASI DAN MENJALANKAN PM2"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📂 Berpindah ke direktori skrip..."
    cd "$SCRIPT_DIR" || exit
    
    echo "🧹 Membersihkan aplikasi PM2 yang mungkin sudah ada..."
    # FIX BUG: Jalankan PM2 sebagai root
    pm2 delete "$APP_NAME" >/dev/null 2>&1 || true
    
    echo "▶️  Memulai aplikasi dengan PM2..."
    # FIX BUG: Jalankan PM2 sebagai root
    if pm2 start ecosystem.config.js; then
        echo "✅ Aplikasi berhasil dimulai dengan PM2."
    else
        echo "⛔ Gagal memulai aplikasi dengan PM2."
        exit 1
    fi
    
    echo "💾 Menyimpan konfigurasi PM2..."
    # FIX BUG: Jalankan PM2 sebagai root
    pm2 save
    
    echo ""
    echo "🔗 Untuk mengaktifkan startup PM2 secara otomatis, jalankan perintah ini dengan sudo:"
    # FIX BUG: Jalankan startup PM2 sebagai root
    local pm2_startup_cmd=$(pm2 startup systemd | tail -1)
    echo "   $pm2_startup_cmd"
    echo ""
    
    # Menampilkan status aplikasi
    echo "📊 Status aplikasi PM2:"
    # FIX BUG: Jalankan PM2 sebagai root
    pm2 status "$APP_NAME"
    
    echo ""
    echo "✅ PM2 BERHASIL DIKONFIGURASI"
}

# --- Eksekusi Utama ---
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║          OPENVPN AGENT DEPLOYMENT             ║"
    echo "║              WITH SNMP MONITORING             ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    
    check_sudo
    get_user_input
    get_snmp_input

    ## PERUBAHAN VENV: Buat direktori skrip di awal
    echo ""
    echo "═══════════════════════════════════════════════"
    echo "📂 PERSIAPAN DIREKTORI"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    echo "📁 Membuat direktori agen di $SCRIPT_DIR..."
    if mkdir -p "$SCRIPT_DIR"; then
        chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR"
        echo "✅ Direktori berhasil dibuat dan kepemilikan diatur."
    else
        echo "⛔ Gagal membuat direktori agen."
        exit 1
    fi

    echo ""
    echo "═══════════════════════════════════════════════"
    echo "🔍 VALIDASI SISTEM"
    echo "═══════════════════════════════════════════════"
    echo ""
    
    if ! find_easy_rsa_path; then
        echo "⛔ Easy-RSA tidak ditemukan. Deployment dibatalkan."
        exit 1
    fi

    if ! check_openvpn_service; then
        if [ ! -f "$OPENVPN_INSTALL_SCRIPT_PATH" ]; then
            echo ""
            echo "⛔ Skrip instalasi server OpenVPN tidak ditemukan di $OPENVPN_INSTALL_SCRIPT_PATH."
            echo "   Tolong pastikan OpenVPN sudah terinstal dan berjalan, atau letakkan skrip instalasi"
            echo "   di lokasi yang benar."
            exit 1
        fi
        echo ""
        echo "▶️  Menjalankan skrip instalasi server OpenVPN..."
        if sudo bash "$OPENVPN_INSTALL_SCRIPT_PATH"; then
            echo "✅ OpenVPN berhasil diinstal dan dikonfigurasi."
        else
            echo "⛔ Gagal menginstal OpenVPN."
            exit 1
        fi
    fi

    # Eksekusi fungsi utama
    install_dependencies
    configure_snmp
    create_env_file
    deploy_scripts
    create_pm2_ecosystem_file
    configure_pm2

    echo ""
    echo "╔═══════════════════════════════════════════════╗"
    echo "║               DEPLOYMENT SELESAI              ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo ""
    echo "🎉 Deployment OpenVPN agent dengan SNMP monitoring selesai dengan sukses!"
    echo ""
    echo "📋 RINGKASAN DEPLOYMENT:"
    echo "   • Server ID: $SERVER_ID"
    echo "   • Aplikasi PM2: $APP_NAME"
    echo "   • Dashboard URL: $DASHBOARD_API_URL"
    echo "   • Direktori OVPN: $OVPN_DIR"
    if [[ "$CONFIGURE_SNMP" =~ ^[yY]$ ]]; then
        echo "   • SNMP: Aktif (Community: $SNMP_COMMUNITY_STRING)"
    else
        echo "   • SNMP: Tidak dikonfigurasi"
    fi
    echo ""
    echo "📁 LOKASI FILE PENTING:"
    echo "   • Direktori agen: $SCRIPT_DIR"
    echo "   • File konfigurasi: $SCRIPT_DIR/.env"
    echo "   • Log aplikasi: $SCRIPT_DIR/logs/"
    echo ""
    echo "🔧 PERINTAH BERGUNA:"
    echo "   • Cek status: pm2 status $APP_NAME"
    echo "   • Lihat log: pm2 logs $APP_NAME"
    echo "   • Restart: pm2 restart $APP_NAME"
    echo "   • Stop: pm2 stop $APP_NAME"
    echo ""
    echo "⚠️  JANGAN LUPA:"
    echo "   • Jalankan perintah startup PM2 yang ditampilkan di atas untuk auto-start"
    echo "   • Pastikan firewall mengizinkan port 8080 untuk agen"
    if [[ "$CONFIGURE_SNMP" =~ ^[yY]$ ]]; then
        echo "   • Pastikan firewall mengizinkan port 161 (UDP) dari IP dashboard untuk SNMP"
    fi
    echo ""
    echo "🌐 Agent dapat diakses di: http://$(hostname -I | awk '{print $1}'):8080/health"
    echo ""
    echo "✅ Deployment berhasil! Agent siap digunakan."
}

# Jalankan fungsi main
main "$@"
