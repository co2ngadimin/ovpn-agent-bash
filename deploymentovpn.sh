#!/bin/bash
#
# deploymentovpn.sh (MODIFIKASI dengan venv)
#
# Skrip ini mengotomatiskan deployment OpenVPN Agent pada server baru.
# Ini akan menginstal dependensi, membuat Python virtual environment (venv),
# menyebarkan skrip agen dan manajer klien, dan mengkonfigurasinya untuk
# dijalankan dengan PM2 dari dalam venv.
#
# Usage: ./deploymentovpn.sh
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

# --- Fungsi ---

# Periksa apakah skrip dijalankan dengan hak akses root (sudo)
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "❌ Tolong jalankan skrip ini dengan sudo: sudo $0"
        exit 1
    fi
    echo "✅ Skrip dijalankan dengan hak akses root."
}

# Fungsi untuk meminta input dari user
get_user_input() {
    echo ""
    while [ -z "$APP_NAME" ]; do
        read -p "📝 Masukkan Nama Aplikasi untuk PM2 (contoh: vpn-agent): " APP_NAME
        if [ -z "$APP_NAME" ]; then
            echo "❌ Nama aplikasi tidak boleh kosong."
        fi
    done

    echo ""
    while [ -z "$AGENT_API_KEY" ]; do
        read -p "📝 Masukkan AGENT_API_KEY (pastikan sama dengan di dashboard): " AGENT_API_KEY
        if [ -z "$AGENT_API_KEY" ]; then
            echo "❌ API Key tidak boleh kosong."
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
                    read -p "📝 Masukkan Alamat IP Dashboard API: " DASHBOARD_HOST_RAW
                    if [[ $DASHBOARD_HOST_RAW =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                        echo "🔎 Melakukan ping ke $DASHBOARD_HOST_RAW..."
                        if ping -c 1 -W 1 "$DASHBOARD_HOST_RAW" > /dev/null 2>&1; then
                            echo "✅ IP Dashboard API ($DASHBOARD_HOST_RAW) berhasil dijangkau."
                            PROTOCOL="https://" # Default HTTPS untuk IP
                            BASE_URL="${PROTOCOL}${DASHBOARD_HOST_RAW}"
                            ip_valid=1
                        else
                            echo "❌ Gagal melakukan ping ke $DASHBOARD_HOST_RAW. Pastikan IP benar dan server up."
                        fi
                    else
                        echo "❌ Format IP tidak valid. Mohon masukkan IP dengan format yang benar."
                    fi
                done
                url_type_valid=1
                ;;
            2)
                local domain_valid=0
                while [ $domain_valid -eq 0 ]; do
                    read -p "📝 Masukkan Nama Domain Dashboard API (contoh: dashboard.example.com atau https://dashboard.example.com): " DASHBOARD_HOST_RAW
                    if [[ -z "$DASHBOARD_HOST_RAW" ]]; then
                        echo "❌ Nama domain tidak boleh kosong."
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
                            echo "❌ Format domain tidak valid. Mohon masukkan domain dengan format yang benar."
                        fi
                    fi
                done
                url_type_valid=1
                ;;
            *)
                echo "❌ Pilihan tidak valid. Silakan masukkan 1 atau 2."
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
            read -p "📝 Masukkan Port Kustom (contoh: 3000): " DASHBOARD_PORT
            if [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] && [ "$DASHBOARD_PORT" -ge 1 ] && [ "$DASHBOARD_PORT" -le 65535 ]; then
                FINAL_PORT_PART=":${DASHBOARD_PORT}"
                port_valid=1
            else
                echo "❌ Port tidak valid. Masukkan angka antara 1 dan 65535."
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
        read -p "📝 Masukkan ID Server (contoh: SERVER-01): " SERVER_ID
        if [ -z "$SERVER_ID" ]; then
            echo "❌ ID Server tidak boleh kosong."
        fi
    done

    echo ""
    local default_ovpn_dir="/home/$SUDO_USER/ovpn"
    read -p "📝 Masukkan direktori untuk file OVPN (default: $default_ovpn_dir): " OVPN_DIR_INPUT
    OVPN_DIR=${OVPN_DIR_INPUT:-$default_ovpn_dir}
    echo "✅ Direktori OVPN: $OVPN_DIR"
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
    echo "❌ Jalur Easy-RSA index.txt tidak ditemukan di lokasi umum. Deployment gagal."
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
    echo "❌ Layanan atau proses OpenVPN tidak ditemukan. Deployment dibatalkan."
    return 1
}

# Instal dependensi sistem, Node.js, dan Python
install_dependencies() {
    echo "⚙️  Menginstal dependensi sistem..."
    apt-get update
    apt-get install -y openvpn python3 python3-pip python3-venv expect curl dos2unix 

    # Perbaiki line endings script ini
    dos2unix "$0"

    echo "⚙️  Menginstal Node.js secara manual..."
    if ! command -v node &> /dev/null; then
        echo "Node.js tidak ditemukan. Menginstal..."
        curl -o /tmp/"$NODE_DIR".tar.gz "$NODE_URL"
        tar -xzf /tmp/"$NODE_DIR".tar.gz -C /tmp/
        mkdir -p /usr/local/lib/nodejs
        cp -Rv /tmp/"$NODE_DIR" /usr/local/lib/nodejs/

        ln -s /usr/local/lib/nodejs/"$NODE_DIR"/bin/node /usr/bin/node
        ln -s /usr/local/lib/nodejs/"$NODE_DIR"/bin/npm /usr/bin/npm
        ln -s /usr/local/lib/nodejs/"$NODE_DIR"/bin/npx /usr/bin/npx

        echo "✅ Verifikasi instalasi Node.js..."
        node -v
        echo "✅ Node.js terinstal."
    else
        echo "☑️ Node.js sudah terinstal. Melewati."
    fi

    echo "⚙️  Menginstal PM2..."
    sudo npm install -g pm2

    # Konfigurasi PM2 PATH
    echo "🔗 Mengkonfigurasi PM2 PATH..."
    NPM_GLOBAL_BIN_PATH=$(sudo -u "$SUDO_USER" bash -c "npm config get prefix")/bin
    echo "ℹ️ Jalur global NPM yang terdeteksi untuk $SUDO_USER: $NPM_GLOBAL_BIN_PATH"

    SHELL_PROFILE=""
    if [ "$USER" = "root" ] || [ "$SUDO_USER" = "root" ]; then
        HOME_DIR="/root"
    else
        HOME_DIR="/home/$SUDO_USER"
    fi
    
    if [ -f "$HOME_DIR/.zshrc" ]; then
        SHELL_PROFILE="$HOME_DIR/.zshrc"
    elif [ -f "$HOME_DIR/.bashrc" ]; then
        SHELL_PROFILE="$HOME_DIR/.bashrc"
    else
        touch "$HOME_DIR/.bashrc"
        SHELL_PROFILE="$HOME_DIR/.bashrc"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        if ! grep -q "$NPM_GLOBAL_BIN_PATH" "$SHELL_PROFILE" 2>/dev/null; then
            echo "export PATH=\"\$PATH:$NPM_GLOBAL_BIN_PATH\"" | sudo tee -a "$SHELL_PROFILE" > /dev/null
            export PATH="$PATH:$NPM_GLOBAL_BIN_PATH"
        fi
        if [ -f "$NPM_GLOBAL_BIN_PATH/pm2" ]; then
            ln -sf "$NPM_GLOBAL_BIN_PATH/pm2" /usr/local/bin/pm2
        fi
    fi

    if command -v pm2 &> /dev/null; then
        echo "✅ PM2 dapat diakses dari baris perintah."
        pm2 --version
    else
        echo "❌ Instalasi PM2 mungkin gagal."
    fi

    ## =======================================================
    ## PERUBAHAN VENV: Membuat Virtual Environment dan Instalasi Paket Python
    ## =======================================================
    echo "🐍 Membuat Python virtual environment di $VENV_PATH..."
    # Buat venv sebagai SUDO_USER untuk memastikan kepemilikan yang benar
    sudo -u "$SUDO_USER" python3 -m venv "$VENV_PATH"

    echo "📦 Menginstal dependensi Python di dalam venv..."
    # Jalankan pip dari dalam venv untuk menginstal paket secara lokal
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install --upgrade pip
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install fastapi "uvicorn[standard]" pydantic python-dotenv psutil requests aiohttp

    echo "✅ Dependensi Python terinstal di dalam virtual environment."
    ## =======================================================
}


# Buat file .env dari input user
create_env_file() {
    echo "📄 Membuat file .env..."
    # Gunakan tee untuk membuat file .env dengan izin sudo
    cat << EOF | sudo tee "$SCRIPT_DIR/.env" > /dev/null
AGENT_API_KEY="$AGENT_API_KEY"
SERVER_ID="$SERVER_ID"
DASHBOARD_API_URL="$DASHBOARD_API_URL"
SCRIPT_PATH="$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
OVPN_DIR="$OVPN_DIR"
EASY_RSA_INDEX_PATH="$EASY_RSA_INDEX_PATH"
EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_SERVER_NAME_PATH"
EOF
    echo "✅ File .env berhasil dibuat."
}


# Deploy skrip Python dan Bash
deploy_scripts() {
    echo "📂 Menyebarkan skrip ke $SCRIPT_DIR..."
    # Direktori sudah dibuat sebelumnya, hanya memastikan ada folder logs
    mkdir -p "$SCRIPT_DIR/logs"

    # Simpan skrip agen Python
    echo "📄 Menulis skrip agen Python ke $SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME..."
    # Gunakan sudo tee untuk menulis file sebagai SUDO_USER
    cat << '_PYTHON_SCRIPT_EOF_' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME" > /dev/null
# [ ISI KONTEN main.py YANG SAMA SEPERTI ASLINYA DI SINI ]
# main.py (Modifikasi Agen FastAPI Anda)

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from subprocess import run, PIPE
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import os
import re
import psutil
import requests
import asyncio
from datetime import datetime, timezone
import hashlib # Import modul hashlib untuk checksum

# Load .env variables
load_dotenv()

app = FastAPI()

# Env config
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
SERVER_ID = os.getenv("SERVER_ID")
DASHBOARD_API_URL = os.getenv("DASHBOARD_API_URL")
SCRIPT_PATH = os.getenv("SCRIPT_PATH", "./openvpn-client-manager.sh")
OVPN_DIR = os.getenv("OVPN_DIR", "/home/ovpn") # Direktori tempat .ovpn disimpan
EASY_RSA_INDEX_PATH = os.getenv("EASY_RSA_INDEX_PATH", "/etc/openvpn/easy-rsa/pki/index.txt")
EASY_RSA_SERVER_NAME_PATH = os.getenv("EASY_RSA_SERVER_NAME_PATH", "/etc/openvpn/easy-rsa/SERVER_NAME_GENERATED")


if not AGENT_API_KEY:
    raise RuntimeError("Missing AGENT_API_KEY in .env")
if not SERVER_ID:
    raise RuntimeError("Missing SERVER_ID in .env")
if not DASHBOARD_API_URL:
    raise RuntimeError("Missing DASHBOARD_API_URL in .env")
if not os.path.exists(EASY_RSA_INDEX_PATH):
    raise RuntimeError(f"Easy-RSA index.txt not found at {EASY_RSA_INDEX_PATH}")

# Global variable to store the last sent checksum for VPN profiles
last_vpn_profiles_checksum = None

# --- Middleware for auth (untuk akses ke endpoint agen ini dari Dasbor/lainnya) ---
@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    auth = request.headers.get("Authorization")
    # PERHATIAN: Endpoint /users (POST) sekarang juga memerlukan otentikasi
    # Jika Anda ingin /users (POST) tanpa otentikasi, tambahkan kembali ke daftar pengecualian.
    # Namun, SANGAT disarankan untuk mengautentikasi semua endpoint yang memodifikasi state.
    if request.url.path not in ["/health", "/stats"] and (not auth or not auth.startswith("Bearer ") or auth.split(" ")[1] != AGENT_API_KEY):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)

# --- Utility Functions ---
def sanitize_username(username: str) -> str:
    # First, strip any leading/trailing whitespace, including newlines
    stripped_username = username.strip()
    # Then, remove non-alphanumeric characters and convert to lowercase
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '', stripped_username).lower()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,30}$", sanitized):
        raise ValueError("Invalid username format")
    return sanitized

def get_openvpn_service_status() -> str:
    try:
        result = run(["systemctl", "is-active", "openvpn@server"], stdout=PIPE, stderr=PIPE, text=True)
        # Perbaiki logika perbandingan string: gunakan == untuk kecocokan persis
        if result.stdout.strip() == "active":
            return "running"
        elif result.stdout.strip() == "inactive": # Tambahkan kondisi eksplisit untuk 'inactive'
            return "stopped"
        else:
            return "error" # Untuk status lain seperti 'failed' atau yang tidak terduga
    except Exception as e:
        print(f"Error checking OpenVPN service status: {e}")
        return "error"

# Fungsi untuk mendapatkan server CN dari file atau fallback
def get_server_cn() -> str:
    if os.path.exists(EASY_RSA_SERVER_NAME_PATH):
        with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
            return f.read().strip()
    return "server_irL5Kfmg3FnRZaGE" # Fallback, make sure this is your default

# Fungsi untuk mem-parse index.txt dan mengembalikan profil serta checksum
def parse_index_txt() -> tuple[list[dict], str]:
    profiles = []
    if not os.path.exists(EASY_RSA_INDEX_PATH):
        return [], "" # Return empty list and empty checksum if file not found

    try:
        with open(EASY_RSA_INDEX_PATH, 'r') as f:
            raw_content = f.read()
            # Hitung checksum dari konten file mentah
            checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()

            # Reset pointer file untuk membaca baris per baris untuk parsing
            f.seek(0)

            server_cn = get_server_cn()

            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 6: # Ensure enough parts for relevant data
                    cert_status = parts[0] # V, R, E

                    # Check for empty expiration date (indicated by 'Z' only or missing field)
                    expiration_date_str = parts[1]
                    expiration_date = None
                    if expiration_date_str and expiration_date_str != 'Z':
                        try:
                            match = re.match(r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', expiration_date_str)
                            if match:
                                year, month, day, hour, minute, second = match.groups()
                                full_year = int(year)
                                if full_year < 70: # Certificates expire in 20xx
                                    full_year += 2000
                                else: # Certificates expire in 19xx
                                    full_year += 1900

                                iso_format_str = f"{full_year}-{month}-{day}T{hour}:{minute}:{second}Z"
                                expiration_date = datetime.strptime(iso_format_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

                        except ValueError:
                            print(f"Warning: Could not parse expiration date: {expiration_date_str}")
                            expiration_date = None # Set to None if parsing fails

                    # Revocation date processing (similar logic)
                    revocation_date = None
                    if cert_status == 'R' and len(parts) >= 3 and parts[2] and parts[2] != 'Z':
                        revocation_date_str = parts[2]
                        try:
                            match = re.match(r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', revocation_date_str)
                            if match:
                                year, month, day, hour, minute, second = match.groups()
                                full_year = int(year)
                                if full_year < 70:
                                    full_year += 2000
                                else:
                                    full_year += 1900
                                iso_format_str = f"{full_year}-{month}-{day}T{hour}:{minute}:{second}Z"
                                revocation_date = datetime.strptime(iso_format_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        except ValueError:
                            print(f"Warning: Could not parse revocation date: {revocation_date_str}")
                            revocation_date = None

                    serial_number = parts[3] # Serial number

                    # The Common Name (CN) is usually the last part, starting with /CN=
                    cn_match = re.search(r'/CN=([^/]+)$', line)
                    username_raw = cn_match.group(1) if cn_match else "unknown"

                    # Lebih agresif membersihkan username dari karakter non-cetak dan whitespace
                    username = "".join(filter(str.isprintable, username_raw)).lower().strip()

                    # Menambahkan representasi heksadesimal untuk debugging karakter tersembunyi
                    hex_username = ':'.join(f'{ord(c):02x}' for c in username)

                    # Exclude the server's own certificate (using normalized CN)
                    if username_raw == server_cn: # Compare raw CN for server exclusion
                        continue

                    # Map Easy-RSA status to your VpnCertificateStatus enum
                    vpn_cert_status = "UNKNOWN"
                    if cert_status == 'V':
                        vpn_cert_status = "VALID"
                    elif cert_status == 'R':
                        vpn_cert_status = "REVOKED"
                    elif cert_status == 'E': # Expired certificate is sometimes marked 'E'
                        vpn_cert_status = "EXPIRED"

                    # --- BARU: Baca konten file OVPN jika profil VALID ---
                    ovpn_file_content = None
                    if vpn_cert_status == "VALID":
                        ovpn_file_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        try:
                            if os.path.exists(ovpn_file_path) and os.access(ovpn_file_path, os.R_OK):
                                with open(ovpn_file_path, "r") as ovpn_f:
                                    ovpn_file_content = ovpn_f.read()
                            else:
                                print(f"Warning: OVPN file not found or not readable for {username} at '{ovpn_file_path}'.")
                        except Exception as e:
                            print(f"Warning: Could not read OVPN file for {username} at '{ovpn_file_path}'. Error: {e}")

                    profiles.append({
                        "username": username, # Use normalized username
                        "status": vpn_cert_status,
                        "expirationDate": expiration_date.isoformat() if expiration_date else None,
                        "revocationDate": revocation_date.isoformat() if revocation_date else None,
                        "serialNumber": serial_number,
                        "ovpnFileContent": ovpn_file_content, # SERTAKAN KEMBALI FIELD INI
                    })
            return profiles, checksum
    except Exception as e:
        print(f"Error parsing index.txt or calculating checksum: {e}")
        return [], ""

# Fungsi untuk mendapatkan daftar user aktif dari management interface OpenVPN
def get_openvpn_active_users_from_status_log() -> list[str]:
    active_users = []
    # Jalur log status OpenVPN. Perhatikan ini sangat penting untuk disesuaikan dengan konfigurasi OpenVPN Anda.
    status_log_path = "/var/log/openvpn/status.log"

    if not os.path.exists(status_log_path):
        print(f"Warning: OpenVPN status log not found at {status_log_path}. Cannot get active users.")
        return []

    try:
        with open(status_log_path, 'r') as f:
            content = f.read()
            f.seek(0) # Reset pointer file setelah membaca untuk debugging

            start_parsing = False
            for line in f:
                line = line.strip()
                # Ini adalah baris yang menandai awal data klien yang sebenarnya
                if line.startswith("Common Name,Real Address"):
                    start_parsing = True
                    continue # Lewati baris header ini

                # Hentikan parsing jika kita mencapai bagian ROUTING TABLE atau GLOBAL STATS
                if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                    break

                # Jika kita sudah melewati header dan baris tidak kosong, parse sebagai data klien
                if start_parsing and line:
                    parts = line.split(',')
                    if len(parts) >= 1:
                        username = parts[0].lower() # Normalisasi ke huruf kecil
                        if username: # Pastikan username tidak kosong setelah normalisasi
                            active_users.append(username)
        return active_users
    except Exception as e:
        print(f"Error parsing OpenVPN status log for active users: {e}")
        return []

# --- Models ---
class CreateUserRequest(BaseModel):
    username: str

# Model for reporting enhanced server status to the dashboard backend
class EnhancedServerStatusReport(BaseModel):
    serverId: str
    cpuUsage: float
    ramUsage: float
    serviceStatus: str
    activeUsers: list[str] # List of usernames currently active on the server

# BARU: Model untuk mengirim data profil lengkap dari agen ke Dasbor
class VpnUserProfileData(BaseModel):
    username: str
    status: str # VALID, REVOKED, PENDING, EXPIRED, UNKNOWN
    expirationDate: str | None = None # ISO format
    revocationDate: str | None = None # ISO format
    serialNumber: str | None = None
    ovpnFileContent: str | None = None # SERTAKAN KEMBALI FIELD INI

class AgentReportRequest(BaseModel):
    nodeMetrics: EnhancedServerStatusReport
    vpnProfiles: list[VpnUserProfileData]


# Model for action log from dashboard
class ActionLogEntry(BaseModel):
    id: str
    action: str
    vpnUserId: str | None = None # This is the VpnUser.id from DB
    details: str | None = None
    # Add other fields as per your ActionLog model in Prisma
    # isExecuted: bool = False # Assuming backend will handle this
    # executedAt: datetime | None = None

# --- Background Task: Report Stats and Process Actions ---
async def background_task_loop():
    global last_vpn_profiles_checksum # Deklarasikan sebagai global

    while True:
        try:
            # 1. Collect Node Metrics and Active Users
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            service_status = get_openvpn_service_status() # Ini yang kita cek
            active_users = get_openvpn_active_users_from_status_log()

            node_metrics_payload = {
                "serverId": SERVER_ID,
                "cpuUsage": cpu,
                "ramUsage": mem.percent,
                "serviceStatus": service_status, # Nilai ini yang penting
                "activeUsers": active_users
            }


            # Send Node Metrics and Active Users (frequent report)
            headers = {"Authorization": f"Bearer {AGENT_API_KEY}"}
            metrics_response = await asyncio.to_thread(
                requests.post,
                f"{DASHBOARD_API_URL}/agent/report-status", # NEW ENDPOINT FOR METRICS
                json=node_metrics_payload,
                headers=headers
            )
            metrics_response.raise_for_status()
            print(f"Sent status report for server {SERVER_ID}")

            # 2. Collect Comprehensive VPN Profile Data (less frequent / delta report)
            current_profiles, current_checksum = parse_index_txt()

            if current_checksum != last_vpn_profiles_checksum:
                vpn_profiles_payload = {
                    "serverId": SERVER_ID,
                    "vpnProfiles": current_profiles # Use list of dicts directly
                }

                # Send VPN Profile Synchronization (less frequent report)
                sync_profiles_response = await asyncio.to_thread(
                    requests.post,
                    f"{DASHBOARD_API_URL}/agent/sync-profiles", # NEW ENDPOINT FOR PROFILES
                    json=vpn_profiles_payload,
                    headers=headers
                )
                sync_profiles_response.raise_for_status()
                print(f"Sent VPN profiles sync for server {SERVER_ID} (checksum changed).")
                last_vpn_profiles_checksum = current_checksum
            else:
                print(f"VPN profiles checksum unchanged for server {SERVER_ID}. Skipping sync.")

            # 3. Check for new ActionLog entries from Dashboard Backend
            action_logs_response = await asyncio.to_thread(
                requests.get,
                f"{DASHBOARD_API_URL}/agent/action-logs?serverId={SERVER_ID}",
                headers=headers
            )
            action_logs_response.raise_for_status()
            pending_actions = action_logs_response.json()

            for action_log in pending_actions:
                try:
                    log_entry = ActionLogEntry(**action_log)
                    print(f"Processing action log: {log_entry.id} - {log_entry.action}")

                    execution_result = {"status": "success", "message": "", "ovpnFileContent": None} # SERTAKAN KEMBALI ovpnFileContent

                    if log_entry.action == "CREATE_USER":
                        username_to_process = log_entry.details # Assuming details contains username
                        if not username_to_process:
                            raise ValueError("Username is missing for CREATE_USER action")
                        try:
                            # Sanitize and normalize username to lowercase before passing to bash script
                            sanitized_username = sanitize_username(username_to_process)

                            result = run([SCRIPT_PATH, "create", sanitized_username], stdout=PIPE, stderr=PIPE, text=True, check=True)
                            ovpn_path = os.path.join(OVPN_DIR, f"{sanitized_username}.ovpn")
                            if not os.path.exists(ovpn_path):
                                raise RuntimeError("Client created but .ovpn file not found")
                            # --- BARU: Baca file OVPN setelah pembuatan dan sertakan dalam hasil ---
                            with open(ovpn_path, "r") as f:
                                execution_result["ovpnFileContent"] = f.read()
                            execution_result["message"] = f"User {sanitized_username} created. OVPN file generated."
                        except Exception as e:
                            execution_result["status"] = "failed"
                            execution_result["message"] = str(e)

                    elif log_entry.action == "REVOKE_USER" or log_entry.action == "DELETE_USER":
                        username_to_process = log_entry.details # Assuming details contains username
                        if not username_to_process:
                            raise ValueError("Username is missing for REVOKE/DELETE_USER action")
                        try:
                            # Sanitize and normalize username to lowercase before passing to bash script
                            sanitized_username = sanitize_username(username_to_process)
                            result = run([SCRIPT_PATH, "revoke", sanitized_username], stdout=PIPE, stderr=PIPE, text=True, check=True)
                            execution_result["message"] = f"User {sanitized_username} revoked."
                        except Exception as e:
                            execution_result["status"] = "failed"
                            execution_result["message"] = str(e)

                    # Report action execution result back to dashboard
                    await asyncio.to_thread(
                        requests.post,
                        f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                        json={
                            "actionLogId": log_entry.id,
                            "status": execution_result["status"],
                            "message": execution_result["message"],
                            "ovpnFileContent": execution_result["ovpnFileContent"] # SERTAKAN KEMBALI FIELD INI
                        },
                        headers=headers
                    )
                    print(f"Reported action log {log_entry.id} as {execution_result['status']}")

                except Exception as e:
                    print(f"Error processing action log {action_log.get('id', 'N/A')}: {e}")
                    try:
                        await asyncio.to_thread(
                            requests.post,
                            f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                            json={
                                "actionLogId": action_log.get('id', 'N/A'),
                                "status": "failed",
                                "message": f"Agent internal error: {e}"
                            },
                            headers=headers
                        )
                    except Exception as report_err:
                        print(f"Failed to report error for action log: {report_err}")

        except requests.exceptions.RequestException as e:
            print(f"Error communicating with dashboard API: {e}")
        except Exception as e:
            print(f"An unexpected error occurred in background task: {e}")

        await asyncio.sleep(10) # Run every 10 seconds

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(background_task_loop())

# --- Endpoints Agen ---
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/stats")
def get_stats():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    return {
        "cpuUsage": cpu,
        "ramUsage": mem.percent
    }

# Endpoint ini sekarang bisa lebih kaya karena parse_index_txt
@app.get("/profiles")
def list_profiles_agent_side():
    profiles, _ = parse_index_txt() # Abaikan checksum di sini
    return profiles

@app.get("/active-users")
def list_active_users_agent_side():
    return {"activeUsers": get_openvpn_active_users_from_status_log()}

@app.post("/users")
async def create_user_direct(data: CreateUserRequest):
    try:
        username = sanitize_username(data.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = run([SCRIPT_PATH, "create", username], stdout=PIPE, stderr=PIPE, text=True)

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr)

    return {"username": username, "message": "User created. OVPN file generation handled by script."} # Sesuaikan respons

@app.delete("/users/{username}")
def revoke_user_direct(username: str):
    try:
        username = sanitize_username(username.strip()) # Pastikan username di-strip di sini juga
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    result = run([SCRIPT_PATH, "revoke", username], stdout=PIPE, stderr=PIPE, text=True)

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=result.stderr)

    return {"detail": f"User {username} revoked"}
_PYTHON_SCRIPT_EOF_
    chmod -v +x "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME"
    echo "✅ Skrip agen Python berhasil di-deploy."

    # Simpan skrip manajer klien
    echo "📄 Menulis skrip manajer klien ke $SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME..."
    cat << 'CLIENT_MANAGER_EOF' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME" > /dev/null
#!/bin/bash
# shellcheck disable=SC2164,SC2034

# Path ke skrip install OpenVPN (pastikan sesuai)
OPENVPN_INSTALL_SCRIPT="/root/ubuntu-22.04-lts-vpn-server.sh"

create_client() {
    local username=$1
    if [ -z "$username" ]; then
        echo "❌ Bro masukkan username. Usage: $0 create <username>"
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
        echo "❌ Bro masukkan username. Usage: $0 revoke <username>"
        exit 1
    fi

    echo "🔍 Nyari nomor client '$username' dari index.txt..."

    # Ambil nomor client dari index.txt (valid client only, case-insensitive)
    local client_number
    client_number=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f2 | nl -w1 -s' ' | \
        awk -v name="$username" 'BEGIN{IGNORECASE=1} $2 == name {print $1; exit}')


    if [ -z "$client_number" ]; then
        echo "❌ Gak nemu client '$username'. Coba cek list pake: ./openvpn-client-manager.sh list"
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
    if [[ -f /etc/openvpn/easy-rsa/pki/index.txt ]]; then
        grep "^V" /etc/openvpn/easy-rsa/pki/index.txt | \
        cut -d '=' -f2 | \
        grep -v '^server_' # Adjust this line if needed
    else
        echo "❌ index.txt gak ketemu di /etc/openvpn/easy-rsa/pki/"
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
    chmod -v +x "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
    echo "✅ Skrip manajer klien berhasil di-deploy."
}

# Buat file konfigurasi PM2 berdasarkan input user
create_pm2_ecosystem_file() {
    echo "📄 Membuat file ecosystem.config.js..."
    # Gunakan sudo tee untuk menulis file sebagai SUDO_USER
    cat << EOF | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/ecosystem.config.js" > /dev/null
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
      DASHBOARD_API_URL: "$DASHBOARD_API_URL",
      SCRIPT_PATH: "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME",
      OVPN_DIR: "$OVPN_DIR",
      EASY_RSA_INDEX_PATH: "$EASY_RSA_INDEX_PATH",
      EASY_RSA_SERVER_NAME_PATH: "$EASY_RSA_SERVER_NAME_PATH"
    },
    output: "$SCRIPT_DIR/logs/agent-out.log",
    error: "$SCRIPT_DIR/logs/agent-err.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }]
};
EOF
    echo "✅ File ecosystem.config.js berhasil dibuat."
}

# Konfigurasi PM2 untuk menjalankan agen Python
configure_pm2() {
    echo "🚀 Mengkonfigurasi PM2..."
    cd "$SCRIPT_DIR" || exit
    # Jalankan pm2 start dan pm2 save sebagai SUDO_USER
    sudo -u "$SUDO_USER" pm2 start ecosystem.config.js
    sudo -u "$SUDO_USER" pm2 save
    # Jalankan pm2 startup untuk membuat script startup sistem
    pm2 startup systemd -u "$SUDO_USER" --hp "/home/$SUDO_USER"
    echo "✅ PM2 dikonfigurasi. Agen sedang berjalan."
}

# --- Eksekusi Utama ---

check_sudo
get_user_input

## PERUBAHAN VENV: Buat direktori skrip di awal
echo "📂 Membuat direktori agen di $SCRIPT_DIR..."
mkdir -p "$SCRIPT_DIR"
chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR"

if ! find_easy_rsa_path; then
    exit 1
fi

if ! check_openvpn_service; then
    if [ ! -f "$OPENVPN_INSTALL_SCRIPT_PATH" ]; then
        echo "❌ Skrip instalasi server OpenVPN tidak ditemukan di $OPENVPN_INSTALL_SCRIPT_PATH."
        echo "Tolong pastikan skrip ada atau perbarui jalurnya di konfigurasi."
        exit 1
    fi
    echo "▶️  Menjalankan skrip instalasi server OpenVPN..."
    sudo bash "$OPENVPN_INSTALL_SCRIPT_PATH"
fi

install_dependencies
create_env_file
deploy_scripts
create_pm2_ecosystem_file
configure_pm2

echo "🎉 Deployment OpenVPN agent dengan venv selesai dengan sukses!"
