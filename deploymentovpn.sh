#!/bin/bash
#
# deploymentovpn.sh (Versi Andal)
#
# Skrip ini mengotomatiskan deployment OpenVPN Agent secara cerdas dan aman.
# Didesain untuk kompatibel dengan berbagai lingkungan server, termasuk yang
# sudah memiliki Node.js melalui NVM atau instalasi standar.
#
# Usage: ./deploymentovpn.sh
#
set -e

# --- Konfigurasi Default ---
PYTHON_AGENT_SCRIPT_NAME="main.py"
CLIENT_MANAGER_SCRIPT_NAME="openvpn-client-manager.sh"
OPENVPN_INSTALL_SCRIPT_PATH="/root/ubuntu-22.04-lts-vpn-server.sh"
NODE_VERSION="v22.17.1" # Versi Node.js jika perlu instalasi manual

# --- Variabel Global ---
SUDO_USER=${SUDO_USER:-$(whoami)}
BASE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT_DIR="$BASE_DIR/openvpn-agent"
VENV_PATH="$SCRIPT_DIR/venv"
EASY_RSA_INDEX_PATH=""
EASY_RSA_SERVER_NAME_PATH=""
PM2_CMD="" # Akan diisi dengan path absolut ke PM2

# --- Variabel Input User ---
AGENT_API_KEY=""
APP_NAME=""
DASHBOARD_API_URL=""
SERVER_ID=""
OVPN_DIR=""

# --- Fungsi Utility ---

# Fungsi untuk logging dengan timestamp dan level
log() {
    local level=$1
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') - [$level] - $*"
}

# Fungsi untuk keluar dengan pesan error
die() {
    log "ERROR" "$*"
    exit 1
}

# --- Fungsi Utama ---

# Periksa hak akses root
check_sudo() {
    log "INFO" "Memeriksa hak akses root..."
    if [ "$EUID" -ne 0 ]; then
        die "Skrip ini harus dijalankan dengan sudo. Coba: sudo $0"
    fi
    log "SUCCESS" "Skrip berjalan dengan hak akses root."
}

# Meminta input dari pengguna
get_user_input() {
    log "INFO" "Memulai sesi input pengguna..."
    # ... (Konten fungsi get_user_input tetap sama seperti sebelumnya) ...
    # Demi keringkasan, fungsi ini tidak ditampilkan ulang di sini.
    # Pastikan untuk menyalin fungsi get_user_input dari skrip Anda sebelumnya.
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
                        if [[ "$DASHBOARD_HOST_RAW" =~ ^(http|https):// ]]; then
                            PROTOCOL=$(echo "$DASHBOARD_HOST_RAW" | grep -oE '^(http|https)://')
                            DASHBOARD_HOST_CLEAN=${DASHBOARD_HOST_RAW#*//}
                        else
                            PROTOCOL="https://"
                            DASHBOARD_HOST_CLEAN=$DASHBOARD_HOST_RAW
                        fi
                        local temp_host_for_validation=${DASHBOARD_HOST_CLEAN%%/*}
                        temp_host_for_validation=${temp_host_for_validation%%:*}
                        if [[ "$temp_host_for_validation" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$ ]]; then
                            echo "✅ Nama Domain ($DASHBOARD_HOST_CLEAN) diterima."
                            BASE_URL="${PROTOCOL}${DASHBOARD_HOST_CLEAN}"
                            domain_valid=1
                        else
                            echo "❌ Format domain tidak valid."
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
                echo "❌ Port tidak valid."
            fi
        done
    fi

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


# Temukan path Easy-RSA secara dinamis
find_easy_rsa_path() {
    log "INFO" "Mencari path Easy-RSA index.txt..."
    local paths_to_check=(
        "/etc/openvpn/easy-rsa/pki/index.txt"
        "/etc/openvpn/pki/index.txt"
        "/usr/share/easy-rsa/pki/index.txt"
        "/etc/easy-rsa/pki/index.txt"
    )
    for path in "${paths_to_check[@]}"; do
        if [ -f "$path" ]; then
            EASY_RSA_INDEX_PATH="$path"
            EASY_RSA_DIR=$(dirname "$(dirname "$path")")
            EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_DIR/SERVER_NAME_GENERATED"
            log "SUCCESS" "Ditemukan path index.txt: $EASY_RSA_INDEX_PATH"
            return 0
        fi
    done
    die "Jalur Easy-RSA index.txt tidak ditemukan. Deployment gagal."
}

# Periksa layanan OpenVPN
check_openvpn_service() {
    log "INFO" "Mencari layanan OpenVPN yang aktif..."
    if systemctl list-units --type=service --state=running | grep -q 'openvpn'; then
        log "SUCCESS" "Layanan OpenVPN ditemukan dan berjalan."
        return 0
    fi
    if pgrep openvpn > /dev/null; then
        log "SUCCESS" "Proses OpenVPN ditemukan, meskipun layanan tidak terdaftar."
        return 0
    fi
    log "WARN" "Layanan atau proses OpenVPN tidak ditemukan."
    return 1
}

# Instalasi dependensi sistem
install_system_dependencies() {
    log "INFO" "Menginstal dependensi sistem dasar (apt)..."
    apt-get update
    apt-get install -y openvpn python3 python3-pip python3-venv expect curl dos2unix
    dos2unix "$0"
    log "SUCCESS" "Dependensi sistem berhasil diinstal."
}

# Fungsi cerdas untuk menginstal Node.js dan PM2
# Ini akan mendeteksi NVM atau instalasi manual sebelumnya
setup_node_and_pm2() {
    log "INFO" "Memulai setup Node.js dan PM2..."

    # 1. Cari perintah PM2 yang sudah ada
    log "INFO" "Mencari instalasi PM2 yang sudah ada..."
    PM2_CMD=$(command -v pm2 || true)

    # 2. Jika tidak ada, coba cari di dalam NVM
    if [ -z "$PM2_CMD" ]; then
        log "WARN" "PM2 tidak ditemukan di PATH standar. Mencari di NVM..."
        # Cek NVM untuk root dan sudo user
        NVM_DIRS=("$HOME/.nvm" "/home/$SUDO_USER/.nvm")
        for NVM_DIR in "${NVM_DIRS[@]}"; do
            if [ -s "$NVM_DIR/nvm.sh" ]; then
                log "INFO" "Menemukan NVM di $NVM_DIR. Mencoba mencari PM2..."
                # Cari pm2 di dalam direktori versi node nvm
                PM2_CANDIDATE=$(find "$NVM_DIR/versions/node" -type f -name "pm2" 2>/dev/null | head -n 1)
                if [ -n "$PM2_CANDIDATE" ]; then
                    PM2_CMD=$PM2_CANDIDATE
                    log "SUCCESS" "Menemukan PM2 di dalam NVM: $PM2_CMD"
                    break
                fi
            fi
        done
    fi

    # 3. Jika masih tidak ada, lakukan instalasi manual
    if [ -z "$PM2_CMD" ]; then
        log "WARN" "PM2 tidak ditemukan. Melakukan instalasi Node.js & PM2 manual..."
        local NODE_INSTALL_DIR="/usr/local/lib/nodejs"
        local NODE_DIR_NAME="node-$NODE_VERSION-linux-x64"
        local NODE_FULL_PATH="$NODE_INSTALL_DIR/$NODE_DIR_NAME"
        local NODE_URL="https://nodejs.org/dist/$NODE_VERSION/$NODE_DIR_NAME.tar.gz"

        if [ ! -d "$NODE_FULL_PATH" ]; then
             log "INFO" "Mengunduh dan menginstal Node.js $NODE_VERSION..."
             curl -sL "$NODE_URL" -o "/tmp/$NODE_DIR_NAME.tar.gz"
             mkdir -p "$NODE_INSTALL_DIR"
             tar -xzf "/tmp/$NODE_DIR_NAME.tar.gz" -C "$NODE_INSTALL_DIR"
             rm "/tmp/$NODE_DIR_NAME.tar.gz"
             log "SUCCESS" "Node.js terinstal di $NODE_FULL_PATH"
        else
            log "INFO" "Direktori Node.js manual sudah ada. Melewati instalasi."
        fi

        log "INFO" "Menginstal PM2 secara global di dalam Node.js manual..."
        "$NODE_FULL_PATH/bin/npm" install -g pm2 --silent

        PM2_CMD="$NODE_FULL_PATH/bin/pm2"
        if [ ! -f "$PM2_CMD" ]; then
            die "Instalasi PM2 manual gagal. File tidak ditemukan di $PM2_CMD"
        fi
        log "SUCCESS" "PM2 berhasil diinstal di $PM2_CMD"
    fi

    # 4. Pastikan PM2 dapat diakses secara global dengan membuat symbolic link
    if [ ! -f "/usr/local/bin/pm2" ]; then
        log "INFO" "Membuat symbolic link untuk PM2 di /usr/local/bin/pm2..."
        ln -sf "$PM2_CMD" /usr/local/bin/pm2
    fi

    # 5. Verifikasi final
    PM2_CMD="/usr/local/bin/pm2" # Gunakan path symlink untuk konsistensi
    if ! $PM2_CMD --version &> /dev/null; then
        die "Verifikasi akhir PM2 gagal. Periksa instalasi dan PATH."
    fi

    log "SUCCESS" "Setup Node.js dan PM2 selesai. Perintah PM2 siap digunakan."
}


# Setup Python Virtual Environment
setup_python_venv() {
    log "INFO" "Membuat Python virtual environment di $VENV_PATH..."
    if [ -d "$VENV_PATH" ]; then
        log "WARN" "Direktori venv sudah ada. Melewati pembuatan."
    else
        sudo -u "$SUDO_USER" python3 -m venv "$VENV_PATH"
        log "SUCCESS" "Virtual environment berhasil dibuat."
    fi

    log "INFO" "Menginstal dependensi Python di dalam venv..."
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install --upgrade pip
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install fastapi "uvicorn[standard]" pydantic python-dotenv psutil requests aiohttp
    log "SUCCESS" "Dependensi Python berhasil diinstal."
}

# Membuat file-file yang diperlukan
create_files() {
    log "INFO" "Membuat file .env, skrip agen, dan skrip manajer..."
    
    # 1. Buat direktori utama dan logs, atur kepemilikan
    mkdir -p "$SCRIPT_DIR/logs"
    chown -R "$SUDO_USER":"$SUDO_USER" "$BASE_DIR"

    # 2. Buat file .env
    tee "$SCRIPT_DIR/.env" > /dev/null << EOF
AGENT_API_KEY="$AGENT_API_KEY"
SERVER_ID="$SERVER_ID"
DASHBOARD_API_URL="$DASHBOARD_API_URL"
SCRIPT_PATH="$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
OVPN_DIR="$OVPN_DIR"
EASY_RSA_INDEX_PATH="$EASY_RSA_INDEX_PATH"
EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_SERVER_NAME_PATH"
EOF

    # 3. Deploy skrip Python (main.py)
    # ... (Konten skrip Python tetap sama seperti sebelumnya) ...
    # Pastikan untuk menyalin konten skrip main.py Anda ke sini.
    tee "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME" > /dev/null << '_PYTHON_SCRIPT_EOF_'
# [ KONTEN LENGKAP main.py DARI SKRIP SEBELUMNYA DIMASUKKAN DI SINI ]
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
    if request.url.path not in ["/health", "/stats"] and (not auth or not auth.startswith("Bearer ") or auth.split(" ")[1] != AGENT_API_KEY):
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
    try:
        result = run(["systemctl", "is-active", "openvpn@server"], stdout=PIPE, stderr=PIPE, text=True)
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
    if os.path.exists(EASY_RSA_SERVER_NAME_PATH):
        with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
            return f.read().strip()
    return "server_irL5Kfmg3FnRZaGE"

def parse_index_txt() -> tuple[list[dict], str]:
    profiles = []
    if not os.path.exists(EASY_RSA_INDEX_PATH):
        return [], ""

    try:
        with open(EASY_RSA_INDEX_PATH, 'r') as f:
            raw_content = f.read()
            checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()
            f.seek(0)
            server_cn = get_server_cn()

            for line in f:
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
                                full_year = int(year) + (2000 if int(year) < 70 else 1900)
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
                                full_year = int(year) + (2000 if int(year) < 70 else 1900)
                                iso_format_str = f"{full_year}-{month}-{day}T{hour}:{minute}:{second}Z"
                                revocation_date = datetime.strptime(iso_format_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                        except ValueError:
                            revocation_date = None

                    serial_number = parts[3]
                    cn_match = re.search(r'/CN=([^/]+)$', line)
                    username_raw = cn_match.group(1) if cn_match else "unknown"
                    username = "".join(filter(str.isprintable, username_raw)).lower().strip()

                    if username_raw == server_cn:
                        continue

                    vpn_cert_status = {"V": "VALID", "R": "REVOKED", "E": "EXPIRED"}.get(cert_status, "UNKNOWN")
                    
                    ovpn_file_content = None
                    if vpn_cert_status == "VALID":
                        ovpn_file_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        if os.path.exists(ovpn_file_path) and os.access(ovpn_file_path, os.R_OK):
                            with open(ovpn_file_path, "r") as ovpn_f:
                                ovpn_file_content = ovpn_f.read()

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
        print(f"Error parsing index.txt: {e}")
        return [], ""

def get_openvpn_active_users_from_status_log() -> list[str]:
    active_users = []
    status_log_path = "/var/log/openvpn/status.log"
    if not os.path.exists(status_log_path):
        return []
    try:
        with open(status_log_path, 'r') as f:
            content = f.read()
            client_list_section = re.search(r"Common Name,Real Address[\s\S]*?ROUTING TABLE", content)
            if client_list_section:
                client_lines = client_list_section.group(0).split('\n')[1:-1]
                for line in client_lines:
                    if line:
                        username = line.split(',')[0].lower()
                        if username:
                            active_users.append(username)
        return active_users
    except Exception as e:
        print(f"Error parsing status log: {e}")
        return []

# --- Models ---
class CreateUserRequest(BaseModel): username: str
class EnhancedServerStatusReport(BaseModel): serverId: str; cpuUsage: float; ramUsage: float; serviceStatus: str; activeUsers: list[str]
class VpnUserProfileData(BaseModel): username: str; status: str; expirationDate: str | None = None; revocationDate: str | None = None; serialNumber: str | None = None; ovpnFileContent: str | None = None
class AgentReportRequest(BaseModel): nodeMetrics: EnhancedServerStatusReport; vpnProfiles: list[VpnUserProfileData]
class ActionLogEntry(BaseModel): id: str; action: str; vpnUserId: str | None = None; details: str | None = None

# --- Background Task ---
async def background_task_loop():
    global last_vpn_profiles_checksum
    while True:
        try:
            headers = {"Authorization": f"Bearer {AGENT_API_KEY}"}
            
            # Report status
            node_metrics_payload = {
                "serverId": SERVER_ID, "cpuUsage": psutil.cpu_percent(interval=None), "ramUsage": psutil.virtual_memory().percent,
                "serviceStatus": get_openvpn_service_status(), "activeUsers": get_openvpn_active_users_from_status_log()
            }
            requests.post(f"{DASHBOARD_API_URL}/agent/report-status", json=node_metrics_payload, headers=headers, timeout=10).raise_for_status()

            # Sync profiles if changed
            current_profiles, current_checksum = parse_index_txt()
            if current_checksum != last_vpn_profiles_checksum:
                vpn_profiles_payload = {"serverId": SERVER_ID, "vpnProfiles": current_profiles}
                requests.post(f"{DASHBOARD_API_URL}/agent/sync-profiles", json=vpn_profiles_payload, headers=headers, timeout=15).raise_for_status()
                last_vpn_profiles_checksum = current_checksum

            # Process actions
            pending_actions = requests.get(f"{DASHBOARD_API_URL}/agent/action-logs?serverId={SERVER_ID}", headers=headers, timeout=10).json()
            for action_log in pending_actions:
                log_entry = ActionLogEntry(**action_log)
                execution_result = {"status": "failed", "message": "Unknown action", "ovpnFileContent": None}
                try:
                    username_to_process = sanitize_username(log_entry.details)
                    if log_entry.action == "CREATE_USER":
                        run([SCRIPT_PATH, "create", username_to_process], check=True, text=True, capture_output=True)
                        ovpn_path = os.path.join(OVPN_DIR, f"{username_to_process}.ovpn")
                        with open(ovpn_path, "r") as f:
                            execution_result["ovpnFileContent"] = f.read()
                        execution_result.update({"status": "success", "message": f"User {username_to_process} created."})
                    elif log_entry.action in ["REVOKE_USER", "DELETE_USER"]:
                        run([SCRIPT_PATH, "revoke", username_to_process], check=True, text=True, capture_output=True)
                        execution_result.update({"status": "success", "message": f"User {username_to_process} revoked."})
                except Exception as e:
                    execution_result["message"] = str(e)
                
                requests.post(f"{DASHBOARD_API_URL}/agent/action-logs/complete", json={"actionLogId": log_entry.id, **execution_result}, headers=headers, timeout=10)

        except Exception as e:
            print(f"Background task error: {e}")
        await asyncio.sleep(15)

@app.on_event("startup")
async def startup_event(): asyncio.create_task(background_task_loop())
@app.get("/health")
def health(): return {"status": "ok"}
@app.get("/stats")
def get_stats(): return {"cpuUsage": psutil.cpu_percent(interval=1), "ramUsage": psutil.virtual_memory().percent}
@app.get("/profiles")
def list_profiles_agent_side(): return parse_index_txt()[0]
@app.get("/active-users")
def list_active_users_agent_side(): return {"activeUsers": get_openvpn_active_users_from_status_log()}
@app.post("/users")
async def create_user_direct(data: CreateUserRequest):
    username = sanitize_username(data.username)
    result = run([SCRIPT_PATH, "create", username], text=True, capture_output=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"detail": "User creation process initiated."}
@app.delete("/users/{username}")
def revoke_user_direct(username: str):
    username = sanitize_username(username)
    result = run([SCRIPT_PATH, "revoke", username], text=True, capture_output=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"detail": f"User {username} revoked"}
_PYTHON_SCRIPT_EOF_


    # 4. Deploy skrip Bash (openvpn-client-manager.sh)
    # ... (Konten skrip Bash tetap sama seperti sebelumnya) ...
    # Pastikan untuk menyalin konten skrip openvpn-client-manager.sh Anda ke sini.
    tee "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME" > /dev/null << 'CLIENT_MANAGER_EOF'
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

    # 5. Atur izin eksekusi
    chmod +x "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME" "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"

    log "SUCCESS" "Semua file berhasil dibuat dan disebarkan."
}

# Konfigurasi dan jalankan PM2
configure_and_run_pm2() {
    log "INFO" "Membuat file konfigurasi PM2 ecosystem.config.js..."
    
    # Gunakan path absolut ke python di dalam venv
    local PYTHON_EXEC="$VENV_PATH/bin/python"

    tee "$SCRIPT_DIR/ecosystem.config.js" > /dev/null << EOF
module.exports = {
  apps: [{
    name: "$APP_NAME",
    script: "$PYTHON_EXEC",
    args: "-m uvicorn main:app --host 0.0.0.0 --port 8080",
    cwd: "$SCRIPT_DIR",
    exec_mode: "fork",
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: "1G",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
    output: "$SCRIPT_DIR/logs/agent-out.log",
    error: "$SCRIPT_DIR/logs/agent-err.log",
  }]
};
EOF
    log "SUCCESS" "File ecosystem.config.js berhasil dibuat."

    log "INFO" "Menjalankan agen dengan PM2..."
    # Pindah ke direktori skrip untuk konteks yang benar
    cd "$SCRIPT_DIR" || die "Gagal pindah ke direktori $SCRIPT_DIR"

    # Hapus proses lama dengan nama yang sama jika ada, untuk menghindari konflik
    $PM2_CMD delete "$APP_NAME" 2>/dev/null || true
    
    # Jalankan sebagai SUDO_USER untuk kepemilikan proses yang benar
    sudo -u "$SUDO_USER" $PM2_CMD start ecosystem.config.js
    
    # Simpan konfigurasi PM2
    sudo -u "$SUDO_USER" $PM2_CMD save
    
    # Buat skrip startup sistem
    $PM2_CMD startup systemd -u "$SUDO_USER" --hp "/home/$SUDO_USER" | sudo -E bash -

    log "SUCCESS" "PM2 berhasil dikonfigurasi. Agen '$APP_NAME' sedang berjalan."
}

# --- Alur Eksekusi Utama ---
main() {
    check_sudo
    get_user_input
    
    if ! check_openvpn_service; then
        if [ ! -f "$OPENVPN_INSTALL_SCRIPT_PATH" ]; then
            die "Skrip instalasi OpenVPN tidak ditemukan di $OPENVPN_INSTALL_SCRIPT_PATH."
        fi
        log "INFO" "Menjalankan skrip instalasi server OpenVPN..."
        bash "$OPENVPN_INSTALL_SCRIPT_PATH"
    fi

    find_easy_rsa_path
    install_system_dependencies
    setup_node_and_pm2
    setup_python_venv
    create_files
    configure_and_run_pm2

    log "SUCCESS" "🎉 Deployment OpenVPN agent selesai dengan sukses! 🎉"
    $PM2_CMD status
}

# Panggil fungsi utama untuk memulai skrip
main
