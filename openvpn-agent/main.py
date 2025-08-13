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
