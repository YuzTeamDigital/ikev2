#!/bin/bash

# Prompt for server domain, username, and password
read -p "Enter server domain (must point to this VPS): " SERVER_DOMAIN
read -p "Enter VPN username: " VPN_USER
read -s -p "Enter VPN password: " VPN_PASS
echo

# Validate input
if [ -z "$SERVER_DOMAIN" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASS" ]; then
    echo "Server domain, username, and password are required."
    exit 1
fi

# --- 1. Install Dependencies ---
apt update
apt install -y strongswan libcharon-extra-plugins libcharon-extauth-plugins \
               libstrongswan-extra-plugins certbot

# Optionally: install firewall if you haven't yet (UFW)
apt install -y ufw

# --- 2. Obtain a Let's Encrypt Certificate ---
# For a non-interactive setup, adjust certbot parameters as needed
# e.g. add --agree-tos, -m your-email@example.com if you want a fully automated run.
# Here we do an interactive run for demonstration.

echo "Obtaining Let's Encrypt certificate for $SERVER_DOMAIN..."

# Stop any service that might be using port 80 if necessary (e.g., nginx or apache).
# systemctl stop nginx apache2 2>/dev/null

certbot certonly --standalone \
  --preferred-challenges http \
  --domain "$SERVER_DOMAIN"

# Check if Certbot succeeded
if [ ! -f "/etc/letsencrypt/live/$SERVER_DOMAIN/fullchain.pem" ]; then
  echo "Let's Encrypt certificate not found. Certbot may have failed."
  exit 1
fi

# --- 3. Create/Link Cert & Key in /etc/ipsec.d ---
# StrongSwan typically expects separate files in /etc/ipsec.d for the server cert and private key.

# Remove old files if they exist
rm -f /etc/ipsec.d/certs/server-cert.pem
rm -f /etc/ipsec.d/private/server-key.pem

# Create symbolic links (or copy them) to Let’s Encrypt certificate and private key
ln -s /etc/letsencrypt/live/$SERVER_DOMAIN/fullchain.pem /etc/ipsec.d/certs/server-cert.pem
ln -s /etc/letsencrypt/live/$SERVER_DOMAIN/privkey.pem   /etc/ipsec.d/private/server-key.pem

# (Optional) If you prefer copying instead of symlinking:
# cp /etc/letsencrypt/live/$SERVER_DOMAIN/fullchain.pem /etc/ipsec.d/certs/server-cert.pem
# cp /etc/letsencrypt/live/$SERVER_DOMAIN/privkey.pem   /etc/ipsec.d/private/server-key.pem

# Adjust permissions if needed (StrongSwan’s private key directory must be readable by root only)
chmod 600 /etc/ipsec.d/private/server-key.pem

# --- 4. Configure ipsec.conf ---
echo "Backing up existing /etc/ipsec.conf and /etc/ipsec.secrets if they exist..."
[ -f /etc/ipsec.conf ] && mv /etc/ipsec.conf /etc/ipsec.conf.bak
[ -f /etc/ipsec.secrets ] && mv /etc/ipsec.secrets /etc/ipsec.secrets.bak

cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no

    # Our public interface/identity
    left=%any
    leftid=@$SERVER_DOMAIN
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0

    # EAP-MSCHAPv2 for user authentication
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity

    # Strong cryptographic proposals
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
EOF

# --- 5. Configure ipsec.secrets ---
cat > /etc/ipsec.secrets <<EOF
: RSA "server-key.pem"
$VPN_USER : EAP "$VPN_PASS"
EOF

# --- 6. Restart/Enable StrongSwan ---
systemctl enable strongswan-starter
systemctl restart strongswan-starter

# --- 7. Configure UFW (Firewall) ---
echo "Configuring UFW..."
yes | ufw allow OpenSSH
yes | ufw allow 80/tcp      # Needed for Let's Encrypt HTTP challenge (optional if re-using)
yes | ufw allow 500/udp
yes | ufw allow 4500/udp
yes | ufw enable

# --- 8. IP Forwarding and NAT ---
DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
if [ -z "$DEFAULT_INTERFACE" ]; then
    echo "Could not determine the default internet-facing interface."
    exit 1
fi

# UFW NAT rules in /etc/ufw/before.rules
if ! grep -q "*nat" /etc/ufw/before.rules; then
    sed -i "/\*filter/i *nat\n-A POSTROUTING -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -m policy --pol ipsec --dir out -j ACCEPT\n-A POSTROUTING -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
fi

# Mangle for TCP MSS
if ! grep -q "*mangle" /etc/ufw/before.rules; then
    sed -i "/\*filter/i *mangle\n-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360\nCOMMIT\n" /etc/ufw/before.rules
fi

# IPsec policy matching
sed -i "/:ufw-not-local - \[0:0\]/a -A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT\n-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT" /etc/ufw/before.rules

# Enable IP forwarding in UFW’s sysctl.conf
sed -i '/^#net\/ipv4\/ip_forward=1/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/conf\/all\/accept_redirects=0/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/conf\/all\/send_redirects=0/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/ip_no_pmtu_disc=1/s/^#//' /etc/ufw/sysctl.conf

yes | ufw disable
yes | ufw enable

echo
echo "====================================================="
echo "StrongSwan IKEv2 VPN setup complete!"
echo "Domain: $SERVER_DOMAIN"
echo "Username: $VPN_USER"
echo "Password: $VPN_PASS"
echo "Certificate from: Let’s Encrypt"
echo "====================================================="
