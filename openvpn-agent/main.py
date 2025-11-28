#!/usr/bin/env python3
# main.py (FINAL VERSION: True RAM-Optimized Stateful Agent)
import os
import sys
import time
import requests
import hashlib
import re
import glob
import json
from datetime import datetime, timezone
from typing import Dict, Optional, List
from dotenv import load_dotenv
import psutil
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

load_dotenv()
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Konfigurasi ---
AGENT_API_KEY = os.getenv("AGENT_API_KEY")
SERVER_ID = os.getenv("SERVER_ID")
DASHBOARD_API_URL = os.getenv("DASHBOARD_API_URL")
SCRIPT_PATH = os.getenv("SCRIPT_PATH", "./openvpn-client-manager.sh")
OVPN_DIRS_STR = os.getenv("OVPN_DIRS", "/root")
OVPN_DIRS = [d.strip() for d in OVPN_DIRS_STR.split(',') if d.strip()]
EASY_RSA_INDEX_PATH = os.getenv("EASY_RSA_INDEX_PATH")
EASY_RSA_SERVER_NAME_PATH = os.getenv("EASY_RSA_SERVER_NAME_PATH")
OVPN_ACTIVITY_LOG_PATH = os.getenv("OVPN_ACTIVITY_LOG_PATH")
OPENVPN_LOG_PATH = os.getenv("OPENVPN_LOG_PATH")
METRICS_INTERVAL = int(os.getenv("METRICS_INTERVAL_SECONDS", "60"))
CPU_RAM_MONITORING_INTERVAL_STR = os.getenv("CPU_RAM_MONITORING_INTERVAL", "60")
LOG_BATCH_SIZE = 500
STATE_FILE_PATH = os.path.join(SCRIPT_DIR, ".agent_state.json")

if CPU_RAM_MONITORING_INTERVAL_STR.lower() == "disabled":
    CPU_RAM_MONITORING_INTERVAL = None
else:
    try:
        CPU_RAM_MONITORING_INTERVAL = int(CPU_RAM_MONITORING_INTERVAL_STR)
        if CPU_RAM_MONITORING_INTERVAL <= 0: raise ValueError
    except (ValueError, TypeError):
        CPU_RAM_MONITORING_INTERVAL = 60

# --- Validasi Konfigurasi ---
if not all([AGENT_API_KEY, SERVER_ID, DASHBOARD_API_URL, EASY_RSA_INDEX_PATH]):
    print("❌ Missing required environment variables. Check .env file.")
    sys.exit(1)

# --- State Management ---
def load_state():
    if not os.path.exists(STATE_FILE_PATH): return {"files": {}}
    try:
        with open(STATE_FILE_PATH, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError): return {"files": {}}

def save_state(state):
    with open(STATE_FILE_PATH, 'w') as f: json.dump(state, f, indent=4)

# --- Global State ---
last_vpn_profiles_checksum = None

# === HELPER FUNCTIONS ===

# << MERGED FROM SCRIPT 2: RAM-optimized checksum calculation
def get_streamed_checksum(filepath: str) -> Optional[str]:
    if not os.path.exists(filepath): return None
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Could not calculate checksum for {filepath}: {e}")
        return None

def get_cpu_usage() -> float:
    return psutil.cpu_percent(interval=0.1)

def get_ram_usage() -> float:
    return psutil.virtual_memory().percent

def find_ovpn_file(username: str) -> Optional[str]:
    target_filename_lower = f"{username.lower()}.ovpn"
    for base_dir in OVPN_DIRS:
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.lower() == target_filename_lower:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            return f.read()
                    except Exception as e:
                        print(f"⚠️  Could not read {file_path}: {e}")
                        continue
    return None

def sanitize_username(username: str) -> str:
    sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '', username.strip()).lower()
    if not re.match(r"^[a-zA-Z0-9_\-]{3,30}$", sanitized):
        raise ValueError("Invalid username format")
    return sanitized

def get_openvpn_service_status() -> str:
    try:
        result = os.system("systemctl is-active --quiet openvpn@server")
        return "running" if result == 0 else "stopped"
    except:
        return "error"

def get_server_cn() -> str:
    if EASY_RSA_SERVER_NAME_PATH and os.path.exists(EASY_RSA_SERVER_NAME_PATH):
        try:
            with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
                return f.read().strip()
        except:
            pass
    return "server_irL5Kfmg3FnRZaGE"

def get_openvpn_active_users() -> list:
    users = []
    status_log_path = "/var/log/openvpn/status.log"
    if not os.path.exists(status_log_path):
        return []
    try:
        with open(status_log_path, 'r') as f:
            content = f.read()
            parsing = False
            for line in content.split('\n'):
                if line.startswith("Common Name,Real Address"):
                    parsing = True
                    continue
                if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                    break
                if parsing and line:
                    parts = line.split(',')
                    if parts and parts[0]:
                        users.append(parts[0].lower())
    except:
        pass
    return users

def run_command(cmd: list) -> None:
    import subprocess
    subprocess.run(cmd, check=True)

# === DATA PARSING FUNCTIONS ===

def parse_full_profiles(encryption_key: bytes) -> list:
    """
    Mem-parse index.txt, mengenkripsi konten .ovpn, dan mengembalikan daftar profil.
    """
    profiles = []
    if not os.path.exists(EASY_RSA_INDEX_PATH):
        return []

    server_cn = get_server_cn()
    try:
        with open(EASY_RSA_INDEX_PATH, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) < 6:
                    continue

                cn_match = re.search(r'/CN=([^/]+)', line)
                username_raw = cn_match.group(1) if cn_match else "unknown"
                if username_raw == server_cn:
                    continue

                username = "".join(filter(str.isprintable, username_raw)).lower().strip()
                cert_status, exp_str, rev_str, serial = parts[0], parts[1], parts[2], parts[3]

                expiration_date, revocation_date = None, None
                try:
                    if exp_str and exp_str != 'Z':
                        dt = datetime.strptime(exp_str, '%y%m%d%H%M%SZ')
                        expiration_date = dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

                try:
                    if cert_status == 'R' and rev_str and rev_str != 'Z':
                        dt = datetime.strptime(rev_str, '%y%m%d%H%M%SZ')
                        revocation_date = dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

                status_map = {'V': 'VALID', 'R': 'REVOKED', 'E': 'EXPIRED'}
                vpn_status = status_map.get(cert_status, "UNKNOWN")

                ovpn_content_plain = find_ovpn_file(username) if vpn_status == "VALID" else None

                encrypted_content = None
                if ovpn_content_plain:
                    try:
                        # Enkripsi konten di sini
                        encrypted_content = encrypt(ovpn_content_plain, encryption_key)
                    except Exception as e:
                        print(f"⚠️  Gagal mengenkripsi profil untuk {username}: {e}")

                profiles.append({
                    "username": username,
                    "status": vpn_status,
                    "expirationDate": expiration_date.isoformat() if expiration_date else None,
                    "revocationDate": revocation_date.isoformat() if revocation_date else None,
                    "serialNumber": serial,
                    "ovpnFileContent": encrypted_content,  # Gunakan konten yang sudah terenkripsi
                })
        return profiles
    except Exception as e:
        print(f"Error parsing index.txt: {e}")
        return []

# --- Fungsi Sinkronisasi Profil ---
def sync_profiles(headers: Dict[str, str], encryption_key: bytes) -> None:
    """
    Memeriksa perubahan pada index.txt dan mengirimkan profil terenkripsi jika ada perubahan.
    """
    global last_vpn_profiles_checksum
    try:
        prof_checksum = get_streamed_checksum(EASY_RSA_INDEX_PATH)
        if prof_checksum and prof_checksum != last_vpn_profiles_checksum:
            print("Change detected, syncing full VPN profiles...")
            # Teruskan kunci enkripsi saat memanggil parse_full_profiles
            full_profiles = parse_full_profiles(encryption_key)

            requests.post(
                f"{DASHBOARD_API_URL}/agent/sync-profiles",
                json={"serverId": SERVER_ID, "vpnProfiles": full_profiles},
                headers=headers,
                timeout=30
            )
            last_vpn_profiles_checksum = prof_checksum
            del full_profiles  # Hapus dari memori setelah dikirim
    except Exception as e:
        print(f"[ERROR] Failed during profile sync: {e}")

# --- ✅ FUNGSI PENGIRIMAN BATCH YANG DIPERBARUI ---
def send_batch(batch: list, endpoint: str, headers: dict) -> bool:
    if not batch: return True
    payload_key = "activityLogs" if "activity" in endpoint else "openvpnLogs"
    payload = {"serverId": SERVER_ID, payload_key: batch}
    try:
        response = requests.post(f"{DASHBOARD_API_URL}{endpoint}", json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        print(f"Successfully sent batch of {len(batch)} logs to {endpoint}.")
        return True
    except requests.RequestException as e:
        print(f"⛔ Failed to send log batch to {endpoint}: {e}. State will not be updated.")
        return False

# --- ✅ FUNGSI PROSES LOG YANG BENAR-BENAR HEMAT RAM ---
def process_log_file(log_key: str, base_path: str, parser_func, endpoint: str, headers: dict):
    agent_state = load_state()
    file_state = agent_state.get("files", {}).get(log_key, {})

    is_first_run = not bool(file_state)

    # --- ✅ PERUBAHAN UTAMA: Logika "Skip" hanya untuk "openvpn_log" ---
    if is_first_run and log_key == "openvpn_log":
        print(f"First run for {log_key}. Skipping all existing content.")
        try:
            current_stat = os.stat(base_path)
            agent_state["files"][log_key] = {"inode": current_stat.st_ino, "position": current_stat.st_size}
            save_state(agent_state)
            print(f"State initialized for {log_key}. Will only process new logs from now on.")
            return
        except FileNotFoundError:
            return
    # --- AKHIR DARI PERUBAHAN ---

    last_inode = file_state.get("inode")
    last_position = file_state.get("position", 0)

    try:
        current_stat = os.stat(base_path)
        current_inode = current_stat.st_ino
    except FileNotFoundError:
        return

    if last_inode and last_inode != current_inode:
        print(f"Log rotation detected for {log_key}. Resetting position for new file.")
        last_position = 0

    try:
        with open(base_path, 'r', errors='ignore') as f:
            f.seek(last_position)
            batch = []

            while True:
                line = f.readline()
                if not line: break

                parsed = parser_func(line)
                if parsed: batch.append(parsed)

                if len(batch) >= LOG_BATCH_SIZE:
                    if send_batch(batch, endpoint, headers):
                        new_position = f.tell()
                        agent_state["files"][log_key] = {"inode": current_inode, "position": new_position}
                        save_state(agent_state)
                        batch = []
                        time.sleep(1)
                    else:
                        return

            if batch:
                if send_batch(batch, endpoint, headers):
                    new_position = f.tell()
                    agent_state["files"][log_key] = {"inode": current_inode, "position": new_position}
                    save_state(agent_state)
    except Exception as e:
        print(f"[ERROR] in process_log_file for {log_key}: {e}")

def encrypt(plain_text: str, key: bytes) -> str:
    """Enkripsi teks menggunakan AES-GCM dan mengembalikan string Base64."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    # Gabungkan nonce, tag, dan ciphertext, lalu encode ke Base64
    # Nonce (16 bytes) + Tag (16 bytes) + Ciphertext
    encrypted_payload = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
    return encrypted_payload

# === MAIN AGENT LOOP (OPTIMIZED BATCH SYNC) ===
def main_loop():
    headers = {"Authorization": f"Bearer {AGENT_API_KEY}", "Content-Type": "application/json"}

    SECRET_KEY_STR = os.getenv("SECRET_ENCRYPTION_KEY")
    if not SECRET_KEY_STR or len(SECRET_KEY_STR) < 32:
        print("❌ SECRET_ENCRYPTION_KEY tidak valid atau terlalu pendek di .env. Harus minimal 32 karakter.")
        sys.exit(1)
    
    SECRET_KEY_BYTES = SECRET_KEY_STR.encode('utf-8')[:32]

    while True:
        try:
            # 5. Proses Aksi dari Dashboard
            resp = requests.get(f"{DASHBOARD_API_URL}/agent/action-logs?serverId={SERVER_ID}", headers=headers, timeout=10)
            actions = resp.json()
            
            # --- 🔥 OPTIMIZATION START: Flagging System ---
            needs_profile_sync = False 
            # ---------------------------------------------

            for action in actions:
                try:
                    action_id, action_type, details = action.get('id'), action.get('action'), action.get('details')
                    result = {"status": "success", "message": "", "ovpnFileContent": None}

                    action_performed = False
                    
                    print(f"Processing action: {action_type} for {details}...") # Debug print dikit

                    if action_type == "CREATE_USER":
                        username = sanitize_username(details)
                        run_command([SCRIPT_PATH, "create", username])
                        ovpn_content = find_ovpn_file(username)
                        if ovpn_content:
                            result["ovpnFileContent"] = encrypt(ovpn_content, SECRET_KEY_BYTES)
                        else:
                            result["ovpnFileContent"] = None
                        result["message"] = f"User {username} created."
                        action_performed = True
                    
                    elif action_type in ["REVOKE_USER", "DELETE_USER"]:
                        username = sanitize_username(details)
                        run_command([SCRIPT_PATH, "revoke", username])
                        result["message"] = f"User {username} revoked."
                        action_performed = True
                    
                    elif action_type == "DECOMMISSION_AGENT":
                        try:
                            requests.post(f"{DASHBOARD_API_URL}/agent/decommission-complete", json={"serverId": SERVER_ID}, headers=headers, timeout=5)
                        except:
                            pass
                        import subprocess
                        subprocess.run([
                            "sudo", "systemd-run", "--on-active=3s",
                            "/bin/bash", f"{SCRIPT_DIR}/self-destruct.sh", os.getenv("SERVICE_NAME", "openvpn-agent")
                        ])
                        print("💀 Shutting down for self-destruct...")
                        sys.exit(0)

                    # Kirim laporan per-item (ini tetep di dalam loop biar dashboard cepet dapet update status per user)
                    if action_type != "DECOMMISSION_AGENT":
                        requests.post(f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                            json={"actionLogId": action_id, **result}, headers=headers, timeout=10)

                    # Kalau sukses, tandain flag jadi True. JANGAN SYNC DISINI.
                    if action_performed:
                        needs_profile_sync = True

                except Exception as e:
                    print(f"⚠️ Error processing action {action.get('id')}: {e}")
                    requests.post(f"{DASHBOARD_API_URL}/agent/action-logs/complete",
                        json={"actionLogId": action.get('id'), "status": "failed", "message": str(e)},
                        headers=headers, timeout=10)

            # --- 🔥 OPTIMIZATION END: Batch Sync ---
            # Cek flag setelah keluar dari loop
            if needs_profile_sync:
                print(f"⚡ Batch actions completed. Triggering SINGLE profile sync.")
                time.sleep(1) # Kasih jeda dikit biar file system settle
                sync_profiles(headers, SECRET_KEY_BYTES)
            # ---------------------------------------

            # 1. Report Status
            status_payload = {
                "serverId": SERVER_ID,
                "serviceStatus": get_openvpn_service_status(),
                "activeUsers": get_openvpn_active_users(),
            }
            if CPU_RAM_MONITORING_INTERVAL is not None:
                status_payload["cpuUsage"] = get_cpu_usage()
                status_payload["ramUsage"] = get_ram_usage()
            requests.post(f"{DASHBOARD_API_URL}/agent/report-status", json=status_payload, headers=headers, timeout=10)

            # 2. Sync Full Profiles (Routine check)
            # Ini tetep jalan buat handle kasus manual change di server (bukan via dashboard)
            # Karena ada checksum check di dalem sync_profiles, ini aman & murah kalau gak ada perubahan.
            sync_profiles(headers, SECRET_KEY_BYTES)

            # Proses log
            process_log_file(
                log_key="activity_log",
                base_path=OVPN_ACTIVITY_LOG_PATH,
                parser_func=parse_activity_log_line,
                endpoint="/agent/report-activity-logs",
                headers=headers
            )
            process_log_file(
                log_key="openvpn_log",
                base_path=OPENVPN_LOG_PATH,
                parser_func=package_raw_log_line,
                endpoint="/agent/report-openvpn-logs",
                headers=headers
            )

        except requests.exceptions.RequestException as e:
            print(f"[NETWORK ERROR] Could not connect to dashboard: {e}")
        except Exception as e:
            print(f"[FATAL ERROR] in main loop: {e}")

        print(f"--- Cycle complete, sleeping for {METRICS_INTERVAL} seconds ---")
        time.sleep(METRICS_INTERVAL)

# --- Parser/Packager ---
def parse_activity_log_line(line: str) -> Optional[Dict]:
    parts = line.strip().split(',')
    if len(parts) < 2: return None
    try:
        ts = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S').isoformat() + "Z"
        action, username = parts[1], (parts[2] if len(parts) > 2 else None)
        public_ip, vpn_ip, bytes_r, bytes_s = (parts[3] if len(parts) > 3 else None), None, None, None
        if action == "CONNECT" and len(parts) > 4: vpn_ip = parts[4]
        elif action == "DISCONNECT" and len(parts) > 5:
            bytes_r, bytes_s = int(parts[4]), int(parts[5])
        return {"timestamp": ts, "action": action, "username": username, "publicIp": public_ip, "vpnIp": vpn_ip, "bytesReceived": bytes_r, "bytesSent": bytes_s}
    except (ValueError, IndexError): return None

def package_raw_log_line(line: str) -> Optional[Dict]:
    stripped_line = line.strip()
    if stripped_line: return {"message": stripped_line}
    return None

if __name__ == "__main__":
    print("🚀 OpenVPN Agent (True RAM-Optimized) Started")
    main_loop()
