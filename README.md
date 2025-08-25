# 🚀 OpenVPN Management Agent Deployment

A **powerful automation script** to deploy a management agent on your
OpenVPN server.\
The agent is a **FastAPI app** that chats with your central dashboard →
manage VPN users & monitor server status remotely.

![Linux](https://img.shields.io/badge/Ubuntu-22.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-PM2-339933?logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

------------------------------------------------------------------------

## ✨ Features

-   ⚙️ **Automated Setup** → Installs Python3, Node.js, PM2.\
-   🖥️ **Interactive Config** → User-friendly CLI prompts.\
-   🔄 **Process Management** → Runs as PM2 background service
    (auto-restart).\
-   📡 **SNMP Monitoring** → (Optional) dashboard CPU, RAM & network
    stats.\
-   🔑 **Secure** → API key authentication + proper file permissions.\
-   📦 **Self-contained** → All scripts + venv neatly in one directory.\
-   💣 **Remote Decommissioning** → Self-destruct on command.

------------------------------------------------------------------------

## 📋 Prerequisites

You'll need:\
- Ubuntu **22.04 LTS** server 🐧
- `sudo` / root access
- Existing OpenVPN installation and script from this installation: https://www.cyberciti.biz/faq/ubuntu-22-04-lts-set-up-openvpn-server-in-5-minutes/ (Need the `ubuntu-22.04-lts-vpn-server.sh` file)
- Dashboard details:
- `AGENT_API_KEY` 🔑
- `SERVER_ID` 🆔
- `DASHBOARD_API_URL` 🌍

------------------------------------------------------------------------

## ⚡ Installation

Clone repo:

``` bash
wget https://raw.githubusercontent.com/SoramiKS/ovpn-agent-bash/refs/heads/main/deploymentovpn.sh -O install.sh
```

Or upload the script:

``` bash
chmod +x install.sh
sudo ./install.sh
```

Follow prompts:\
- **App Name** → name for PM2 process\
- **API Key / Server ID / Dashboard URL** → from your dashboard\
- **OVPN Directory** → where `.ovpn` files are stored\
- **SNMP** → configure or skip

------------------------------------------------------------------------

## 🔧 Post-Install

Enable **PM2 Startup** on reboot (script will tell you the command):

``` bash
sudo env PATH=$PATH:/usr/bin pm2 startup systemd -u <user> --hp /home/<user>
```

Update firewall:

``` bash
# Agent API
sudo ufw allow from <DASHBOARD_IP> to any port 8080 proto tcp

# SNMP (if enabled)
sudo ufw allow from <DASHBOARD_IP> to any port 161 proto udp
```

Check health:

``` bash
curl http://127.0.0.1:8080/health
# {"status":"ok"}
```

------------------------------------------------------------------------

## 📂 File Structure

    openvpn-agent/
    ├── .env                      # Secrets & env variables
    ├── ecosystem.config.js       # PM2 config
    ├── main.py                   # FastAPI agent
    ├── openvpn-client-manager.sh # Helper for user mgmt
    ├── self-destruct.sh          # Clean uninstall
    ├── venv/                     # Python venv
    └── logs/
        ├── agent-out.log
        └── agent-err.log

------------------------------------------------------------------------

## 🛠️ Managing the Agent (PM2)

``` bash
# Check status
sudo pm2 status vpn-agent

# Logs
sudo pm2 logs vpn-agent

# Restart
sudo pm2 restart vpn-agent

# Stop
sudo pm2 stop vpn-agent
```

------------------------------------------------------------------------

## 💡 Pro Tips

-   Run with `screen` or `tmux` if you're paranoid about SSH
    disconnects.\
-   Use a strong `AGENT_API_KEY`. Don't let your VPN become a public
    café WiFi. ☕\
-   Wanna nuke everything? Run `self-destruct.sh` --- agent yeets itself
    💥.

------------------------------------------------------------------------

## 🔗 Integration with OpenVPN Management Dashboard

This agent is designed to work with the OpenVPN Management Dashboard (https://github.com/SoramiKS/openvpn-dashboard).
The dashboard provides a modern web interface for monitoring and managing OpenVPN servers connected to this agent.

Integration steps:

1. Install and run the dashboard from the following repository:
🔗 https://github.com/SoramiKS/openvpn-dashboard
2. Use the same AGENT_API_KEY on both the dashboard and the agent.
3. Ensure the SERVER_ID in the agent is unique for each server.
4. Once the agent is running, the dashboard will automatically detect the connection and display server information along with a list of VPN profiles.
   
------------------------------------------------------------------------


## 📜 License
This project is licensed under the **MIT License**.
