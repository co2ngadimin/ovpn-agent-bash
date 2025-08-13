module.exports = {
  apps: [{
    name: "agen",
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
      AGENT_API_KEY: "kj",
      SERVER_ID: "n",
      DASHBOARD_API_URL: "https://192.168.1.92/api",
      SCRIPT_PATH: "/home/ovpn/openvpn-agent/openvpn-client-manager.sh",
      OVPN_DIR: "/home/ovpn/ovpn",
      EASY_RSA_INDEX_PATH: "/etc/openvpn/easy-rsa/pki/index.txt",
      EASY_RSA_SERVER_NAME_PATH: "/etc/openvpn/easy-rsa/SERVER_NAME_GENERATED"
    },
    output: "/home/ovpn/openvpn-agent/logs/agent-out.log",
    error: "/home/ovpn/openvpn-agent/logs/agent-err.log",
    log_date_format: "YYYY-MM-DD HH:mm:ss",
  }]
};
