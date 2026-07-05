#!/bin/bash
# PRISM Environment Bootstrap Script
# Run this script with sudo to configure the VM sandbox.

set -euo pipefail

echo "[*] Installing core dependencies..."
apt update && apt upgrade -y
apt install -y auditd audispd-plugins python3 python3-pip python3-venv gcc make git jq curl net-tools procps lsof strace ltrace vim tree

echo "[*] Configuring auditd baseline..."
systemctl stop auditd || true
cp /etc/audit/audit.rules /etc/audit/audit.rules.bak || true
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak || true

sed -i 's/^max_log_file =.*/max_log_file = 50/' /etc/audit/auditd.conf
sed -i 's/^num_logs =.*/num_logs = 5/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action =.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf

systemctl enable auditd
systemctl start auditd

echo "[*] Creating prism_test user..."
if ! id "prism_test" &>/dev/null; then
    useradd -m -s /bin/bash prism_test
    echo "prism_test:TestPass123!" | chpasswd
fi

echo "[*] Deploying dummy_cred_holder.sh..."
cat << 'EOF' > /usr/local/bin/dummy_cred_holder.sh
#!/bin/bash
# PRISM test target — holds dummy credential string in memory
FAKE_SECRET="password=DUMMY_LAB_SECRET_PRISM_2024"
echo "[dummy_cred_holder] Running as PID $$, holding dummy credential in memory."
echo "[dummy_cred_holder] This process is the T1003 scan target."
while true; do
    sleep 60
done
EOF
chmod +x /usr/local/bin/dummy_cred_holder.sh

echo "[*] Bootstrap complete. Please verify network isolation manually."
