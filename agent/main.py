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
# BUG FIX: No need to check for the file here, as it will be accessed with sudo
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
    # BUG FIX: Check service status with sudo
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
    # BUG FIX: Run as root, so no sudo needed
    try:
        if os.path.exists(EASY_RSA_SERVER_NAME_PATH):
            with open(EASY_RSA_SERVER_NAME_PATH, 'r') as f:
                return f.read().strip()
    except Exception as e:
        print(f"Error reading server CN file: {e}")
    return "server_irL5Kfmg3FnRZaGE"

def parse_index_txt() -> tuple[list[dict], str]:
    profiles = []
    # BUG FIX: Run as root, so no sudo needed
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
                            # BUG FIX: Run as root, so no sudo needed
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
    # BUG FIX: Run as root, so no sudo needed
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
                # BUG FIX: Run as root, so no sudo needed
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

            # 1. Report Node Metrics (service status only, CPU/RAM via SNMP)
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
                    
                    # Run the manager script with sudo as it needs root privileges
                    if log_entry.action == "CREATE_USER":
                        username = sanitize_username(log_entry.details)
                        run(["sudo", SCRIPT_PATH, "create", username], check=True)
                        ovpn_path = os.path.join(OVPN_DIR, f"{username}.ovpn")
                        # Read the OVPN file without sudo as it's run as root
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

                            # Let the shell handle redirection and backgrounding
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
    # Run the manager script with sudo
    result = run(["sudo", SCRIPT_PATH, "create", username], stdout=PIPE, stderr=PIPE, text=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"username": username, "message": "User created."}

@app.delete("/users/{username}")
def revoke_user_direct(username: str):
    username = sanitize_username(username)
    # Run the manager script with sudo
    result = run(["sudo", SCRIPT_PATH, "revoke", username], stdout=PIPE, stderr=PIPE, text=True)
    if result.returncode != 0: raise HTTPException(status_code=500, detail=result.stderr)
    return {"detail": f"User {username} revoked"}

