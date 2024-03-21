#!/bin/bash

# Prompt for server domain, username, and password
read -p "Enter server domain: " SERVER_DOMAIN
read -p "Enter VPN username: " VPN_USER
read -s -p "Enter VPN password: " VPN_PASS
echo

# Validate input
if [ -z "$SERVER_DOMAIN" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASS" ]; then
    echo "Server domain, username, and password are required."
    exit 1
fi

# Install StrongSwan and related packages
apt update
apt install strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libtss2-tcti-tabrmd0 -y

# Create PKI directory and set permissions
mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki

# Generate CA key and certificate
pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem
pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem --type rsa --dn "CN=VPN root CA" --outform pem > ~/pki/cacerts/ca-cert.pem

# Generate server key and certificate
pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem
pki --pub --in ~/pki/private/server-key.pem --type rsa \
    | pki --issue --lifetime 1825 \
    --cacert ~/pki/cacerts/ca-cert.pem \
    --cakey ~/pki/private/ca-key.pem \
    --dn "CN=$SERVER_DOMAIN" --san "$SERVER_DOMAIN" \
    --flag serverAuth --flag ikeIntermediate --outform pem \
    > ~/pki/certs/server-cert.pem

# Copy certificates to the ipsec directory
cp -r ~/pki/* /etc/ipsec.d/

# Backup the original ipsec.conf and ipsec.secrets
mv /etc/ipsec.conf{,.original}
mv /etc/ipsec.secrets{,.original}

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
    left=%any
    leftid=@$SERVER_DOMAIN
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
EOF

# Create new ipsec.secrets with user and pass
cat > /etc/ipsec.secrets <<EOF
: RSA "server-key.pem"
$VPN_USER : EAP "$VPN_PASS"
EOF

# Restart StrongSwan
systemctl restart strongswan-starter

# Configure UFW
yes | ufw allow OpenSSH
yes | ufw enable
yes | ufw allow 500,4500/udp

# First, backup the original before.rules file
cp /etc/ufw/before.rules /etc/ufw/before.rules.backup

# Prepare the new sections to be added
NAT_RULES="*nat
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
COMMIT"

MANGLE_RULES="*mangle
-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT"

# Insert NAT and mangle rules before the first occurrence of *filter in before.rules
awk -v nat="$NAT_RULES" -v mangle="$MANGLE_RULES" '/\*filter/ && !modif { print nat; print mangle; modif=1 } {print}' /etc/ufw/before.rules.backup > /etc/ufw/before.rules

# Enable IP forwarding and disable ICMP redirects
sed -i '/^#net\/ipv4\/ip_forward=1/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/conf\/all\/accept_redirects=0/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/conf\/all\/send_redirects=0/s/^#//' /etc/ufw/sysctl.conf
sed -i '/^#net\/ipv4\/ip_no_pmtu_disc=1/s/^#//' /etc/ufw/sysctl.conf

# Reload UFW to apply changes
yes | ufw disable
yes | ufw enable

echo "VPN setup completed."
