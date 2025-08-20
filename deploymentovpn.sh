#!/bin/bash
#
# deploymentovpn.sh (Versi Final Lengkap)
#
# Skrip ini mengotomatiskan deployment OpenVPN Agent pada server baru.
# Ini akan menginstal dependensi, membuat Python virtual environment (venv),
# menyebarkan skrip agen dan manajer klien, dan mengkonfigurasinya untuk
# dijalankan dengan PM2 dari dalam venv.
#
# Usage: sudo ./deploymentovpn.sh
#
set -e

# --- Konfigurasi Default ---
PYTHON_AGENT_SCRIPT_NAME="main.py"
CLIENT_MANAGER_SCRIPT_NAME="openvpn-client-manager.sh"
SELF_DESTRUCT_SCRIPT_NAME="self-destruct.sh"
OPENVPN_INSTALL_SCRIPT_PATH="/root/ubuntu-22.04-lts-vpn-server.sh"
NODE_VERSION="v22.17.1"
NODE_DIR="node-$NODE_VERSION-linux-x64"
NODE_URL="https://nodejs.org/dist/$NODE_VERSION/$NODE_DIR.tar.gz"

# Dapatkan nama pengguna yang menjalankan sudo
SUDO_USER=${SUDO_USER:-$(whoami)}
# Dapatkan path absolut dari direktori tempat skrip ini berada
BASE_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# Tentukan direktori kerja utama
SCRIPT_DIR="$BASE_DIR/openvpn-agent"
VENV_PATH="$SCRIPT_DIR/venv"
EASY_RSA_INDEX_PATH=""
EASY_RSA_SERVER_NAME_PATH=""

# Variabel yang akan diisi oleh input user
AGENT_API_KEY=""
APP_NAME=""
DASHBOARD_API_URL=""
SERVER_ID=""
OVPN_DIR=""

# --- Fungsi ---

check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        echo "❌ Tolong jalankan skrip ini dengan sudo: sudo $0"
        exit 1
    fi
    echo "✅ Skrip dijalankan dengan hak akses root."
}

get_user_input() {
    echo ""
    while [ -z "$APP_NAME" ]; do
        read -p "📝 Masukkan Nama Aplikasi untuk PM2 (contoh: vpn-agent): " APP_NAME
    done

    echo ""
    while [ -z "$AGENT_API_KEY" ]; do
        read -p "📝 Masukkan AGENT_API_KEY (dari dashboard): " AGENT_API_KEY
    done

    local url_type_valid=0
    local DASHBOARD_HOST_RAW=""
    local PROTOCOL=""
    local BASE_URL=""

    while [ $url_type_valid -eq 0 ]; do
        echo ""
        read -p "Pilih jenis alamat Dashboard API (1=IP, 2=Domain): " URL_CHOICE
        case "$URL_CHOICE" in
            1)
                read -p "📝 Masukkan Alamat IP Dashboard API: " DASHBOARD_HOST_RAW
                PROTOCOL="https://"
                BASE_URL="${PROTOCOL}${DASHBOARD_HOST_RAW}"
                url_type_valid=1
                ;;
            2)
                read -p "📝 Masukkan Nama Domain Dashboard API: " DASHBOARD_HOST_RAW
                if [[ "$DASHBOARD_HOST_RAW" =~ ^(http|https):// ]]; then
                    BASE_URL="$DASHBOARD_HOST_RAW"
                else
                    BASE_URL="https://$DASHBOARD_HOST_RAW"
                fi
                url_type_valid=1
                ;;
            *) echo "❌ Pilihan tidak valid." ;;
        esac
    done

    read -p "Apakah Dashboard API menggunakan port kustom? [y/N]: " USE_CUSTOM_PORT
    if [[ "$USE_CUSTOM_PORT" =~ ^[yY]$ ]]; then
        read -p "📝 Masukkan Port Kustom: " DASHBOARD_PORT
        BASE_URL="${BASE_URL}:${DASHBOARD_PORT}"
    fi

    if [[ "$BASE_URL" != */api ]]; then
        DASHBOARD_API_URL="${BASE_URL}/api"
    else
        DASHBOARD_API_URL="${BASE_URL}"
    fi
    echo "✅ URL Dashboard API diatur ke: $DASHBOARD_API_URL"

    echo ""
    while [ -z "$SERVER_ID" ]; do
        read -p "📝 Masukkan ID Server (dari dashboard): " SERVER_ID
    done

    echo ""
    local default_ovpn_dir="/home/$SUDO_USER/ovpn"
    read -p "📝 Masukkan direktori file OVPN (default: $default_ovpn_dir): " OVPN_DIR_INPUT
    OVPN_DIR=${OVPN_DIR_INPUT:-$default_ovpn_dir}
    echo "✅ Direktori OVPN: $OVPN_DIR"
}

find_easy_rsa_path() {
    echo "🔍 Mencari jalur Easy-RSA index.txt..."
    local paths_to_check=("/etc/openvpn/easy-rsa/pki/index.txt" "/etc/openvpn/pki/index.txt" "/usr/share/easy-rsa/pki/index.txt")
    for path in "${paths_to_check[@]}"; do
        if [ -f "$path" ]; then
            EASY_RSA_INDEX_PATH="$path"
            EASY_RSA_DIR=$(dirname "$EASY_RSA_INDEX_PATH" | xargs dirname)
            EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_DIR/SERVER_NAME_GENERATED"
            echo "✅ Ditemukan jalur index.txt: $EASY_RSA_INDEX_PATH"
            return 0
        fi
    done
    echo "❌ Jalur Easy-RSA index.txt tidak ditemukan. Deployment gagal."
    return 1
}

check_openvpn_service() {
    echo "🔎 Memeriksa layanan OpenVPN..."
    if systemctl is-active --quiet "openvpn-server@server" || systemctl is-active --quiet "openvpn@server" || pgrep openvpn > /dev/null; then
        echo "✅ Layanan OpenVPN ditemukan."
        return 0
    else
        echo "❌ Layanan OpenVPN tidak ditemukan."
        return 1
    fi
}

install_dependencies() {
    echo "⚙️  Menginstal dependensi sistem..."
    apt-get update
    # PERBAIKAN: Tambahkan 'at' ke daftar instalasi
    apt-get install -y openvpn python3 python3-pip python3-venv expect curl dos2unix at
    dos2unix "$0"

    if ! command -v node &> /dev/null; then
        echo "⚙️  Menginstal Node.js..."
        curl -o /tmp/"$NODE_DIR".tar.gz "$NODE_URL"
        tar -xzf /tmp/"$NODE_DIR".tar.gz -C /tmp/
        mkdir -p /usr/local/lib/nodejs
        cp -Rv /tmp/"$NODE_DIR" /usr/local/lib/nodejs/
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/node /usr/bin/node
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/npm /usr/bin/npm
        ln -sf /usr/local/lib/nodejs/"$NODE_DIR"/bin/npx /usr/bin/npx
    fi

    echo "⚙️  Menginstal PM2..."
    npm install -g pm2
    
    echo "🐍 Membuat Python virtual environment..."
    sudo -u "$SUDO_USER" python3 -m venv "$VENV_PATH"
    echo "📦 Menginstal dependensi Python..."
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install --upgrade pip
    sudo -u "$SUDO_USER" "$VENV_PATH/bin/pip" install fastapi "uvicorn[standard]" pydantic python-dotenv psutil requests aiohttp
    echo "✅ Semua dependensi berhasil diinstal."
}

create_env_file() {
    echo "📄 Membuat file .env..."
    cat << EOF | sudo tee "$SCRIPT_DIR/.env" > /dev/null
AGENT_API_KEY="$AGENT_API_KEY"
SERVER_ID="$SERVER_ID"
DASHBOARD_API_URL="$DASHBOARD_API_URL"
SCRIPT_PATH="$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
OVPN_DIR="$OVPN_DIR"
EASY_RSA_INDEX_PATH="$EASY_RSA_INDEX_PATH"
EASY_RSA_SERVER_NAME_PATH="$EASY_RSA_SERVER_NAME_PATH"
OVPN_ACTIVITY_LOG_PATH="/var/log/openvpn/user_activity.log"
PM2_APP_NAME="$APP_NAME"
EOF
    echo "✅ File .env berhasil dibuat."
}

deploy_scripts() {
    echo "📂 Menyebarkan skrip ke $SCRIPT_DIR..."
    mkdir -p "$SCRIPT_DIR/logs"

    # --- Skrip Agen Python (main.py) ---
    echo "📄 Menulis skrip agen Python..."
    cat << '_PYTHON_SCRIPT_EOF_' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME" > /dev/null
# main.py (Final Version)
import os
import re
import psutil
import requests
import asyncio
import hashlib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from subprocess import run, PIPE
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime, timezone
from typing import List, Optional

# Definisi SCRIPT_DIR yang andal
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(SCRIPT_DIR, '.env'))

app = FastAPI()

# Konfigurasi dari .env
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
SERVER_ID = os.getenv("SERVER_ID")
DASHBOARD_API_URL = os.getenv("DASHBOARD_API_URL")
SCRIPT_PATH = os.getenv("SCRIPT_PATH")
OVPN_DIR = os.getenv("OVPN_DIR")
EASY_RSA_INDEX_PATH = os.getenv("EASY_RSA_INDEX_PATH")
EASY_RSA_SERVER_NAME_PATH = os.getenv("EASY_RSA_SERVER_NAME_PATH")
OVPN_ACTIVITY_LOG_PATH = os.getenv("OVPN_ACTIVITY_LOG_PATH")
PM2_APP_NAME = os.getenv("PM2_APP_NAME")

# Checksums
last_vpn_profiles_checksum = None
last_activity_log_checksum = None

class ActionLogEntry(BaseModel):
    id: str
    action: str
    details: Optional[str] = None

def sanitize_username(username: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_\-]', '', username.strip()).lower()

def get_openvpn_service_status() -> str:
    try:
        result = run(["systemctl", "is-active", "openvpn-server@server"], capture_output=True, text=True)
        status = result.stdout.strip()
        if status == "active":
            return "running"
        elif status == "inactive":
            return "stopped"
        else:
            return "error"
    except Exception:
        return "error"

def get_server_cn() -> str:
    if EASY_RSA_SERVER_NAME_PATH and os.path.exists(EASY_RSA_SERVER_NAME_PATH):
        with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
            return f.read().strip()
    return "server" # Fallback

def parse_index_txt() -> tuple[list[dict], str]:
    profiles = []
    if not EASY_RSA_INDEX_PATH or not os.path.exists(EASY_RSA_INDEX_PATH): return [], ""
    try:
        with open(EASY_RSA_INDEX_PATH, 'r') as f:
            raw_content = f.read()
            checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()
            f.seek(0)
            server_cn = get_server_cn()
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) < 6: continue
                
                cert_status = parts[0]
                cn_match = re.search(r'/CN=([^/]+)$', line)
                if not cn_match: continue
                
                username_raw = cn_match.group(1).strip()
                if username_raw == server_cn: continue

                username = sanitize_username(username_raw)
                status_map = {'V': 'VALID', 'R': 'REVOKED', 'E': 'EXPIRED'}
                
                expiration_date = None
                if parts[1]:
                    try:
                        dt_str = parts[1].split('Z')[0]
                        expiration_date = datetime.strptime(dt_str, '%y%m%d%H%M%S').replace(tzinfo=timezone.utc).isoformat()
                    except ValueError: pass
                
                revocation_date = None
                if cert_status == 'R' and parts[2]:
                    try:
                        dt_str = parts[2].split('Z')[0]
                        revocation_date = datetime.strptime(dt_str, '%y%m%d%H%M%S').replace(tzinfo=timezone.utc).isoformat()
                    except ValueError: pass

                ovpn_file_content = None
                if cert_status == 'V':
                    ovpn_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                    if os.path.exists(ovpn_path):
                        with open(ovpn_path, 'r') as ovpn_f:
                            ovpn_file_content = ovpn_f.read()

                profiles.append({
                    "username": username,
                    "status": status_map.get(cert_status, "UNKNOWN"),
                    "expirationDate": expiration_date,
                    "revocationDate": revocation_date,
                    "serialNumber": parts[3],
                    "ovpnFileContent": ovpn_file_content
                })
        return profiles, checksum
    except Exception as e:
        print(f"Error parsing index.txt: {e}")
        return [], ""

def parse_activity_logs() -> tuple[list[dict], str]:
    logs = []
    raw_content = ""
    log_files = [OVPN_ACTIVITY_LOG_PATH]
    if OVPN_ACTIVITY_LOG_PATH:
        log_files.append(f"{OVPN_ACTIVITY_LOG_PATH}.1")

    for log_file in log_files:
        if log_file and os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    raw_content += f.read()
            except Exception as e:
                print(f"Could not read log file {log_file}: {e}")

    if not raw_content: return [], ""
    
    checksum = hashlib.md5(raw_content.encode('utf-8')).hexdigest()
    for line in raw_content.strip().split('\n'):
        parts = line.strip().split(',')
        if len(parts) < 2: continue
        try:
            logs.append({
                "timestamp": datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S').isoformat() + "Z",
                "action": parts[1],
                "username": parts[2] if len(parts) > 2 and parts[2] else None,
                "publicIp": parts[3] if len(parts) > 3 and parts[3] else None,
                "vpnIp": parts[4] if len(parts) > 4 and parts[4] else None,
                "bytesReceived": int(parts[5]) if len(parts) > 5 and parts[1] == "DISCONNECT" else None,
                "bytesSent": int(parts[6]) if len(parts) > 6 and parts[1] == "DISCONNECT" else None,
            })
        except (ValueError, IndexError):
            continue
    return logs, checksum

async def background_task_loop():
    global last_vpn_profiles_checksum, last_activity_log_checksum
    while True:
        try:
            headers = {"Authorization": f"Bearer {AGENT_API_KEY}"}
            
            # 1. Laporkan metrik
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            status = get_openvpn_service_status()
            
            metrics_payload = {
                "serverId": SERVER_ID,
                "cpuUsage": cpu,
                "ramUsage": mem.percent,
                "serviceStatus": status
            }
            requests.post(f"{DASHBOARD_API_URL}/agent/report-status", json=metrics_payload, headers=headers, timeout=5)

            # 2. Sinkronisasi profil VPN
            current_profiles, current_profiles_checksum = parse_index_txt()
            if current_profiles_checksum != last_vpn_profiles_checksum:
                profiles_payload = {"serverId": SERVER_ID, "vpnProfiles": current_profiles}
                requests.post(f"{DASHBOARD_API_URL}/agent/sync-profiles", json=profiles_payload, headers=headers, timeout=10)
                last_vpn_profiles_checksum = current_profiles_checksum

            # 3. Sinkronisasi log aktivitas
            current_logs, current_logs_checksum = parse_activity_logs()
            if current_logs_checksum and current_logs_checksum != last_activity_log_checksum:
                logs_payload = {"serverId": SERVER_ID, "activityLogs": current_logs}
                requests.post(f"{DASHBOARD_API_URL}/agent/report-activity-logs", json=logs_payload, headers=headers, timeout=10)
                last_activity_log_checksum = current_logs_checksum

            # 4. Proses perintah dari dashboard
            response = requests.get(f"{DASHBOARD_API_URL}/agent/action-logs?serverId={SERVER_ID}", headers=headers, timeout=5)
            response.raise_for_status()
            pending_actions = response.json()

            for action_log in pending_actions:
                log_entry = ActionLogEntry(**action_log)
                print(f"Processing action: {log_entry.action} for log ID: {log_entry.id}")
                
                result_payload = {"actionLogId": log_entry.id, "status": "failed", "message": "", "ovpnFileContent": None}
                
                try:
                    if log_entry.action == "CREATE_USER":
                        username = sanitize_username(log_entry.details)
                        run([SCRIPT_PATH, "create", username], check=True)
                        ovpn_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        with open(ovpn_path, "r") as f:
                            result_payload["ovpnFileContent"] = f.read()
                        result_payload["message"] = f"User {username} created."
                        result_payload["status"] = "success"

                    elif log_entry.action == "REVOKE_USER":
                        username = sanitize_username(log_entry.details)
                        run([SCRIPT_PATH, "revoke", username], check=True)
                        result_payload["message"] = f"User {username} revoked."
                        result_payload["status"] = "success"
                    
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
                            command = f"sudo /bin/bash {SCRIPT_DIR}/self-destruct.sh {PM2_APP_NAME}"
                            schedule_command = f'echo "{command}" | at now + 10 seconds'
                            run(schedule_command, shell=True, check=True)
                        continue

                    requests.post(f"{DASHBOARD_API_URL}/agent/action-logs/complete", json=result_payload, headers=headers, timeout=5)

                except Exception as e:
                    print(f"Error processing action log {log_entry.id}: {e}")
                    result_payload["message"] = f"Agent internal error: {e}"
                    requests.post(f"{DASHBOARD_API_URL}/agent/action-logs/complete", json=result_payload, headers=headers, timeout=5)

        except Exception as e:
            print(f"Error in background task: {e}")
        
        await asyncio.sleep(10)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(background_task_loop())

@app.get("/health")
def health():
    return {"status": "ok"}
_PYTHON_SCRIPT_EOF_
    chmod -v +x "$SCRIPT_DIR/$PYTHON_AGENT_SCRIPT_NAME"
    echo "✅ Skrip agen Python berhasil di-deploy."

    # --- Skrip Manajer Klien (openvpn-client-manager.sh) ---
    echo "📄 Menulis skrip manajer klien..."
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
    local client_number
    client_number=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f2 | nl -w1 -s' ' | \
        awk -v name="$username" 'BEGIN{IGNORECASE=1} $2 == name {print $1; exit}')

    if [ -z "$client_number" ]; then
        echo "❌ Gak nemu client '$username'."
        exit 1
    fi

    echo "✅ Ketemu! '$username' ada di nomor $client_number"
    expect <<EOF
        spawn sudo "$OPENVPN_INSTALL_SCRIPT"
        expect "Select an option*" { send "2\r" }
        expect "Select one client*" { send "$client_number\r" }
        expect eof
EOF
    echo "✅ Client '$username' udah direvoke."
}

# Main entrypoint
case "$1" in
    create)
        create_client "$2"
        ;;
    revoke)
        revoke_client "$2"
        ;;
    *)
        echo "Usage: $0 {create|revoke} <username>"
        exit 1
        ;;
esac
CLIENT_MANAGER_EOF
    chmod -v +x "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME"
    echo "✅ Skrip manajer klien berhasil di-deploy."

    # --- Skrip Penghapusan Mandiri (self-destruct.sh) ---
    echo "📄 Menulis skrip penghapusan mandiri..."
    cat << 'SELF_DESTRUCT_EOF' | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/$SELF_DESTRUCT_SCRIPT_NAME" > /dev/null
#!/bin/bash
# self-destruct.sh (Final Version)
set -e
if [ "$EUID" -ne 0 ]; then
    echo "❌ Skrip ini harus dijalankan dengan sudo."
    exit 1
fi
PM2_APP_NAME="$1"
AGENT_DIR=$(dirname "$(readlink -f "$0")")
echo "🛑 Menerima perintah penghapusan mandiri untuk '$PM2_APP_NAME'..."
echo "[-] Menghentikan dan menghapus proses PM2..."
pm2 stop "$PM2_APP_NAME"
pm2 delete "$PM2_APP_NAME"
pm2 save --force
echo "🗑️ Menghapus direktori instalasi agen: $AGENT_DIR"
rm -rf "$AGENT_DIR"
echo "✅ Proses penghapusan mandiri agen selesai."
SELF_DESTRUCT_EOF
    chmod -v +x "$SCRIPT_DIR/$SELF_DESTRUCT_SCRIPT_NAME"
    echo "✅ Skrip penghapusan mandiri berhasil di-deploy."
}

create_pm2_ecosystem_file() {
    echo "📄 Membuat file ecosystem.config.js..."
    cat << EOF | sudo -u "$SUDO_USER" tee "$SCRIPT_DIR/ecosystem.config.js" > /dev/null
module.exports = {
  apps: [{
    name: "$APP_NAME",
    script: "$VENV_PATH/bin/python",
    args: "-m uvicorn main:app --host 0.0.0.0 --port 8080",
    cwd: "$SCRIPT_DIR",
    env: {
      NODE_ENV: "production",
      AGENT_API_KEY: "$AGENT_API_KEY",
      SERVER_ID: "$SERVER_ID",
      DASHBOARD_API_URL: "$DASHBOARD_API_URL",
      SCRIPT_PATH: "$SCRIPT_DIR/$CLIENT_MANAGER_SCRIPT_NAME",
      OVPN_DIR: "$OVPN_DIR",
      EASY_RSA_INDEX_PATH: "$EASY_RSA_INDEX_PATH",
      EASY_RSA_SERVER_NAME_PATH: "$EASY_RSA_SERVER_NAME_PATH",
      OVPN_ACTIVITY_LOG_PATH: "/var/log/openvpn/user_activity.log",
      PM2_APP_NAME: "$APP_NAME"
    },
    output: "$SCRIPT_DIR/logs/agent-out.log",
    error: "$SCRIPT_DIR/logs/agent-err.log",
  }]
};
EOF
    echo "✅ File ecosystem.config.js berhasil dibuat."
}

configure_pm2() {
    echo "🚀 Mengkonfigurasi PM2..."
    cd "$SCRIPT_DIR" || exit
    # Hentikan proses lama jika ada, sebelum memulai yang baru
    sudo -u "$SUDO_USER" pm2 delete "$APP_NAME" || true
    sudo -u "$SUDO_USER" pm2 start ecosystem.config.js
    sudo -u "$SUDO_USER" pm2 save
    
    echo "💡 Jalankan perintah berikut secara manual untuk mengaktifkan startup PM2:"
    # Perintah startup harus dijalankan sebagai root, dan akan menghasilkan perintah lain untuk dijalankan
    pm2 startup systemd -u "$SUDO_USER" --hp "/home/$SUDO_USER"
}

# --- Eksekusi Utama ---
check_sudo
get_user_input

echo "📂 Membuat direktori agen di $SCRIPT_DIR..."
mkdir -p "$SCRIPT_DIR"
chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR"

if ! find_easy_rsa_path; then exit 1; fi
if ! check_openvpn_service; then
    if [ -f "$OPENVPN_INSTALL_SCRIPT_PATH" ]; then
        echo "▶️ Menjalankan skrip instalasi server OpenVPN..."
        sudo bash "$OPENVPN_INSTALL_SCRIPT_PATH"
    else
        echo "❌ OpenVPN tidak berjalan dan skrip instalasi tidak ditemukan."
        exit 1
    fi
fi

install_dependencies
create_env_file
deploy_scripts
create_pm2_ecosystem_file
configure_pm2

echo "🎉 Deployment OpenVPN agent selesai dengan sukses!"
