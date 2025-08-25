module.exports = {
  apps: [{
    name: "vpn-agent",
    script: "/home/ovpn/openvpn-agent/venv/bin/python",
    args: "-m uvicorn main:app --host 0.0.0.0 --port 8080",
    cwd: "/home/ovpn/openvpn-agent",
    exec_mode: "fork",
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "production",
      AGENT_API_KEY: "admin123",
      SERVER_ID: "4dc1c830-c585-4146-acf1-2daf5726487d",
      PM2_APP_NAME: "vpn-agent",
      DASHBOARD_API_URL: "http://192.168.1.92:3000/api",
      SCRIPT_PATH: "/home/ovpn/openvpn-agent/openvpn-client-manager.sh",
      OVPN_DIR: "/root",
      EASY_RSA_INDEX_PATH: "/etc/openvpn/easy-rsa/pki/index.txt",
      EASY_RSA_SERVER_NAME_PATH: "/etc/openvpn/easy-rsa/SERVER_NAME_GENERATED",
      OVPN_ACTIVITY_LOG_PATH: "/var/log/openvpn/user_activity.log"
    },
    output: "/home/ovpn/openvpn-agent/logs/agent-out.log",
    error: "/home/ovpn/openvpn-agent/logs/agent-err.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }]
};
