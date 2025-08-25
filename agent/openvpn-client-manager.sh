#!/bin/bash
# shellcheck disable=SC2164,SC2034

# Path to the OpenVPN install script (ensure it's correct)
OPENVPN_INSTALL_SCRIPT="/root/ubuntu-22.04-lts-vpn-server.sh"

create_client() {
    local username=$1
    if [ -z "$username" ]; then
        echo "⛔ Please provide a username. Usage: $0 create <username>"
        exit 1
    fi

    echo "➕ Creating new client: $username"
    # MODIFICATION: Run the OpenVPN installation script with sudo
    printf "1\n%s\n1\n" "$username" | sudo "$OPENVPN_INSTALL_SCRIPT"
    echo "✅ Client '$username' created successfully."
}

revoke_client() {
    local username="$1"

    if [ -z "$username" ]; then
        echo "⛔ Please provide a username. Usage: $0 revoke <username>"
        exit 1
    fi

    echo "🔍 Finding client number for '$username' from index.txt..."

    # Get client number from index.txt (valid clients only, case-insensitive)
    # BUG FIX: Use sudo to read the index.txt file
    local client_number
    client_number=$(sudo tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f2 | nl -w1 -s' ' | \
        awk -v name="$username" 'BEGIN{IGNORECASE=1} $2 == name {print $1; exit}')


    if [ -z "$client_number" ]; then
        echo "⛔ Client '$username' not found. Try listing clients with: ./openvpn-client-manager.sh list"
        exit 1
    fi

    echo "✅ Found it! '$username' is number $client_number"
    echo "⚙️  Sending input to the script to revoke..."

    expect <<EOF
        spawn sudo "$OPENVPN_INSTALL_SCRIPT"
        expect "Select an option*" { send "2\r" }
        expect "Select one client*" { send "$client_number\r" }
        expect eof
EOF

    echo "✅ Client '$username' has been revoked. RIP 🪦"
}

list_clients() {
    echo "📋 Listing active clients from Easy-RSA index.txt..."
    # BUG FIX: Use sudo to read the index.txt file
    if [[ -f /etc/openvpn/easy-rsa/pki/index.txt ]]; then
        sudo grep "^V" /etc/openvpn/easy-rsa/pki/index.txt | \
        cut -d '=' -f2 | \
        grep -v '^server_' # Adjust this line if needed
    else
        echo "⛔ index.txt not found at /etc/openvpn/easy-rsa/pki/"
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
