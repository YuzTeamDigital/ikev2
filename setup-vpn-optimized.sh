#!/usr/bin/env bash
###############################################################################
# A script to install and configure an IKEv2 IPsec VPN server using StrongSwan
# on a Debian/Ubuntu system, using a Let’s Encrypt certificate and UFW for
# firewall management.
#
# USAGE:
#   1. Run as root or via sudo.
#   2. Follow the on-screen prompts for server domain, your email (for Let’s Encrypt),
#      VPN username, and VPN password.
#
# KEY POINTS:
#   - Uses Let’s Encrypt for a trusted, signed certificate (2048-bit RSA by default).
#   - Opens port 80 for HTTP validation (standalone mode).
#   - Sets up IPsec with EAP-MSCHAPv2 authentication.
#   - Configures UFW to allow necessary ports (SSH, 500/udp, 4500/udp).
#   - Ensures IP forwarding, NAT, and IPsec policies are set in UFW.
###############################################################################

set -euo pipefail

###############################################################################
# 1. Check if running as root
###############################################################################
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root or via sudo."
  exit 1
fi

###############################################################################
# 2. Prompt for server domain, Let’s Encrypt email, and VPN credentials
###############################################################################
read -rp "Enter server domain (e.g., vpn.example.com): " SERVER_DOMAIN
read -rp "Enter your email address (for Let's Encrypt): " LE_EMAIL
read -rp "Enter VPN username: " VPN_USER
read -s -rp "Enter VPN password: " VPN_PASS
echo

# Validate inputs
if [[ -z "$SERVER_DOMAIN" || -z "$LE_EMAIL" || -z "$VPN_USER" || -z "$VPN_PASS" ]]; then
    echo "Error: All fields (domain, email, username, password) are required."
    exit 1
fi

###############################################################################
# 3. Install StrongSwan, Certbot, and UFW
###############################################################################
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    strongswan \
    libcharon-extra-plugins \
    libcharon-extauth-plugins \
    libstrongswan-extra-plugins \
    libtss2-tcti-tabrmd0 \
    ufw \
    certbot

###############################################################################
# 4. Configure UFW for SSH, IPsec, and Let’s Encrypt HTTP
###############################################################################
yes | ufw allow OpenSSH
yes | ufw allow 500/udp
yes | ufw allow 4500/udp
yes | ufw allow 80/tcp     # Needed for Let’s Encrypt standalone HTTP validation

# Enable UFW if not already
yes | ufw enable

###############################################################################
# 5. Obtain Let’s Encrypt certificate
###############################################################################
# Stop any service possibly bound to port 80 if needed; in many cases you can
# use --standalone without stopping anything if port 80 is free.
# You could also integrate with an existing web server using --nginx or --apache.
certbot certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --preferred-challenges http \
  -m "$LE_EMAIL" \
  -d "$SERVER_DOMAIN"

# Let’s Encrypt stores certificates in /etc/letsencrypt/live/<domain>/
# fullchain.pem: the certificate + intermediate chain
# privkey.pem:   the private key

###############################################################################
# 6. Configure IPsec
###############################################################################
# Backup existing configs if they exist
if [[ -f /etc/ipsec.conf ]]; then
    cp /etc/ipsec.conf "/etc/ipsec.conf.$(date +%F-%T).bak"
fi
if [[ -f /etc/ipsec.secrets ]]; then
    cp /etc/ipsec.secrets "/etc/ipsec.secrets.$(date +%F-%T).bak"
fi

# Create new ipsec.conf
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

    # Server side
    left=%any
    leftid=@${SERVER_DOMAIN}
    leftcert=/etc/letsencrypt/live/${SERVER_DOMAIN}/fullchain.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0

    # Client side
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity

    # Crypto settings
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
EOF

# Create new ipsec.secrets
# We'll reference Let’s Encrypt's private key and set EAP credentials
cat > /etc/ipsec.secrets <<EOF
: RSA /etc/letsencrypt/live/${SERVER_DOMAIN}/privkey.pem
${VPN_USER} : EAP "${VPN_PASS}"
EOF
chmod 600 /etc/ipsec.secrets

# Enable and restart StrongSwan
systemctl enable strongswan-starter
systemctl restart strongswan-starter

###############################################################################
# 7. Configure UFW NAT, Mangle, and IPsec Policies
###############################################################################
UFW_BEFORE_RULES="/etc/ufw/before.rules"

# Backup before.rules
if [[ -f "${UFW_BEFORE_RULES}" ]]; then
    cp "${UFW_BEFORE_RULES}" "${UFW_BEFORE_RULES}.$(date +%F-%T).bak"
fi

# Determine default network interface
DEFAULT_INTERFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}')
if [[ -z "$DEFAULT_INTERFACE" ]]; then
    echo "Could not determine the default internet-facing interface."
    exit 1
fi

# Insert NAT rules if *nat is not present
if ! grep -q "^*nat" "${UFW_BEFORE_RULES}"; then
    sed -i "/^*filter/i *nat\n-A POSTROUTING -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -m policy --pol ipsec --dir out -j ACCEPT\n-A POSTROUTING -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -j MASQUERADE\nCOMMIT\n" "${UFW_BEFORE_RULES}"
fi

# Insert mangle rules if *mangle is not present
if ! grep -q "^*mangle" "${UFW_BEFORE_RULES}"; then
    sed -i "/^*filter/i *mangle\n-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o $DEFAULT_INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360\nCOMMIT\n" "${UFW_BEFORE_RULES}"
fi

# Ensure IPsec policy matching rules exist in the *filter section
if ! grep -q "ufw-before-forward --match policy --pol ipsec --dir in" "${UFW_BEFORE_RULES}"; then
    sed -i "/:ufw-not-local - \[0:0\]/a -A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT" "${UFW_BEFORE_RULES}"
fi
if ! grep -q "ufw-before-forward --match policy --pol ipsec --dir out" "${UFW_BEFORE_RULES}"; then
    sed -i "/:ufw-not-local - \[0:0\]/a -A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT" "${UFW_BEFORE_RULES}"
fi

echo "Updated ${UFW_BEFORE_RULES} with NAT, mangle, and IPsec policy rules."

###############################################################################
# 8. Enable IP forwarding and disable ICMP redirects in UFW sysctl
###############################################################################
UFW_SYSCTL="/etc/ufw/sysctl.conf"

if [[ -f "${UFW_SYSCTL}" ]]; then
    sed -i '/^#net\/ipv4\/ip_forward=1/s/^#//' "${UFW_SYSCTL}"
    sed -i '/^#net\/ipv4\/conf\/all\/accept_redirects=0/s/^#//' "${UFW_SYSCTL}"
    sed -i '/^#net\/ipv4\/conf\/all\/send_redirects=0/s/^#//' "${UFW_SYSCTL}"
    sed -i '/^#net\/ipv4\/ip_no_pmtu_disc=1/s/^#//' "${UFW_SYSCTL}"
else
    # If sysctl file doesn't exist, append
    {
        echo "net/ipv4/ip_forward=1"
        echo "net/ipv4/conf/all/accept_redirects=0"
        echo "net/ipv4/conf/all/send_redirects=0"
        echo "net/ipv4/ip_no_pmtu_disc=1"
    } >> "${UFW_SYSCTL}"
fi

###############################################################################
# 9. Reload UFW to apply changes
###############################################################################
yes | ufw disable
yes | ufw enable

###############################################################################
# 10. Final Output
###############################################################################
echo "======================================================================="
echo "VPN setup completed successfully!"
echo "Domain: ${SERVER_DOMAIN}"
echo "Certificate: /etc/letsencrypt/live/${SERVER_DOMAIN}/fullchain.pem"
echo "Private Key: /etc/letsencrypt/live/${SERVER_DOMAIN}/privkey.pem"
echo "User: ${VPN_USER}"
echo "Port 80 has been opened for Let’s Encrypt certificate renewal."
echo "======================================================================="
echo "Important: Let’s Encrypt certificates expire in 90 days."
echo "Certbot is installed and will auto-renew. Ensure port 80 remains open."
echo "======================================================================="
