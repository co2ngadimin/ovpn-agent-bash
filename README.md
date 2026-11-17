# 🚀 OpenVPN Management Agent Deployment

A **powerful automation script** to deploy a management agent on your
OpenVPN server.\
The agent is a Python application that communicates with your central dashboard to
manage VPN users & monitor server status remotely.

![Linux](https://img.shields.io/badge/Ubuntu-22.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

------------------------------------------------------------------------

## ✨ Features

-   ⚙️ **Automated Setup** → Installs Python3, dependencies, and creates virtual environment.\
-   🖥️ **Interactive Config** → User-friendly CLI prompts.\
-   🔄 **Process Management** → Runs as systemd background service (auto-restart).\
-   🔑 **Secure** → API key authentication + encrypted communication + proper file permissions.\
-   📦 **Self-contained** → All scripts + venv neatly in one directory.\
-   💣 **Remote Decommissioning** → Self-destruct on command.\
-   📊 **Resource Monitoring** → Reports CPU and RAM usage to dashboard.\
-   📝 **Log Streaming** → Efficiently streams OpenVPN and user activity logs to dashboard.\
-   🔒 **Encrypted File Transfer** → Encrypts .ovpn files before sending to dashboard.

------------------------------------------------------------------------

## 📋 Prerequisites

You'll need:\
- Ubuntu **22.04 LTS** server 🐧 (or compatible Linux distribution)
- `sudo` / root access
- Existing OpenVPN installation (the script can install it if missing)
- Dashboard details:
- `AGENT_API_KEY` 🔑
- `SERVER_ID` 🆔
- `DASHBOARD_API_URL` 🌍

------------------------------------------------------------------------

## ⚡ Installation

Download the deployment script:

``` bash
wget https://raw.githubusercontent.com/SoramiKS/ovpn-agent-bash/refs/heads/main/deploymentovpn.sh -O deploymentovpn.sh
```

Make it executable and run with root privileges:

``` bash
chmod +x deploymentovpn.sh
sudo ./deploymentovpn.sh
```

Follow prompts for configuration:
- **Service Name** → name for systemd service (default: openvpn-agent)
- **API Key / Server ID / Dashboard URL** → from your dashboard
- **Encryption Key** → used to encrypt .ovpn files sent to dashboard
- **OVPN Directories** → directories where .ovpn files are stored
- **System Resources** → RAM limit and monitoring intervals

The script will:
1. Check for existing OpenVPN installation or install if missing
2. Set up Python virtual environment and install dependencies
3. Configure systemd service for automatic startup
4. Set up log rotation for various log files
5. Create configuration files

------------------------------------------------------------------------

## 📡 How the Agent Works

### Status Reporting
The agent periodically sends system status to the dashboard:
- OpenVPN service status (running/stopped)
- Active users list
- CPU usage percentage
- RAM usage percentage

### File Transfer
When a new user is created, the agent:
1. Locates the corresponding .ovpn file in configured directories
2. Encrypts the file content using AES-GCM encryption
3. Sends the encrypted content to the dashboard

### Log Streaming
The agent efficiently streams two types of logs to the dashboard:
- **Activity Logs**: Connection/disconnection events with user details
- **OpenVPN Logs**: Raw OpenVPN server logs

Both log types are streamed using a stateful approach that:
- Remembers the last processed position in each log file
- Handles log rotation automatically
- Processes logs in batches to optimize network usage
- Keeps RAM usage low by reading files line-by-line

------------------------------------------------------------------------

## ⚙️ Configuration

The deployment script generates a `.env` file with the following configuration:

```env
# API credentials and connection details
AGENT_API_KEY="your_api_key_here"
SERVER_ID="unique_server_identifier"
DASHBOARD_API_URL="https://dashboard.domain.com/api"

# File paths
SCRIPT_PATH="/path/to/openvpn-agent/openvpn-client-manager.sh"
OVPN_DIRS="/root,/home/openvpn"
EASY_RSA_INDEX_PATH="/etc/openvpn/easy-rsa/pki/index.txt"
EASY_RSA_SERVER_NAME_PATH="/etc/openvpn/easy-rsa/SERVER_NAME_GENERATED"
OVPN_ACTIVITY_LOG_PATH="/var/log/openvpn/user_activity.log"
OPENVPN_LOG_PATH="/var/log/openvpn/openvpn.log"

# Service configuration
SERVICE_NAME="openvpn-agent"
METRICS_INTERVAL_SECONDS="60"
CPU_RAM_MONITORING_INTERVAL="60"
SECRET_ENCRYPTION_KEY="encryption_key_at_least_32_characters_long"
```

------------------------------------------------------------------------

## 🔧 Managing the Agent

After installation, manage the agent using systemd:

``` bash
# Check status
sudo systemctl status openvpn-agent

# View logs
sudo journalctl -u openvpn-agent -f

# Restart
sudo systemctl restart openvpn-agent

# Stop
sudo systemctl stop openvpn-agent

# Disable auto-start
sudo systemctl disable openvpn-agent
```

------------------------------------------------------------------------

## 📂 File Structure

    openvpn-agent/
    ├── .env                      # Secrets & env variables
    ├── main.py                   # Main Python agent
    ├── openvpn-client-manager.sh # Helper for user management
    ├── self-destruct.sh          # Clean uninstall script
    ├── venv/                     # Python virtual environment
    └── logs/
        └── agent.log             # Agent execution logs

------------------------------------------------------------------------

## Upgrade agent (node yang sudah terpasang)

Jalankan sebagai root di node (ganti `<git-ref>` dengan branch/tag/commit):

```bash
curl -fsSL https://raw.githubusercontent.com/co2ngadimin/ovpn-agent-bash/<git-ref>/upgrade-agent.sh | sudo bash -s -- <git-ref>
```

Script hanya mengganti `main.py` (backup `main.py.bak.<timestamp>`), restart service agent, dan rollback otomatis jika service tidak aktif. `.env`, `.agent_state.json`, OpenVPN, PM2, dan snmpd tidak disentuh. Nama service default `openvpn-agent`; override dengan `SERVICE_NAME=...`.

> **Jangan jalankan ulang `deploymentovpn.sh` untuk upgrade.**

## 🛠️ Requirements and Dependencies

The agent requires the following system packages:
- `bash` (primary scripting environment)
- `python3` (3.x recommended)
- `python3-pip` (for installing Python packages)
- `python3-venv` (for creating virtual environments)
- `dos2unix` (for handling line endings)
- `at` (for scheduling tasks)

Python dependencies installed automatically:
- `python-dotenv` (for loading .env files)
- `requests` (for HTTP communication)
- `psutil` (for system monitoring)
- `pycryptodome` (for file encryption)

Additional requirements:
- Access to OpenVPN installation script (can be downloaded automatically)
- Read access to Easy-RSA index.txt file
- Write access to log directories

------------------------------------------------------------------------

## 💡 Pro Tips

-   Run with `screen` or `tmux` during installation to prevent SSH disconnections.
-   Use a strong `AGENT_API_KEY` and `SECRET_ENCRYPTION_KEY`.
-   Configure firewall to allow only necessary connections.
-   Need to remove the agent completely? Run `self-destruct.sh`.

------------------------------------------------------------------------

## 🔗 Integration with OpenVPN Management Dashboard

This agent is designed to work with the OpenVPN Management Dashboard.
The dashboard provides a modern web interface for monitoring and managing OpenVPN servers connected to this agent.

👉 [OpenVPN Dashboard Repository](https://github.com/SoramiKS/openvpn-dashboard)

Integration steps:
1. Install and run the dashboard from the repository.
2. Use the same AGENT_API_KEY on both the dashboard and the agent.
3. Ensure the SERVER_ID in the agent is unique for each server.
4. Once the agent is running, the dashboard will automatically detect the connection and display server information along with a list of VPN profiles.

------------------------------------------------------------------------


## 📜 License
This project is licensed under the **MIT License****.
