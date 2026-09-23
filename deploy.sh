#!/bin/bash
# ==============================================================================
# AegisScan Cloud VPS 1-Click Deployment Script (Ubuntu / Debian)
# DigitalOcean • Hetzner • AWS EC2 • Linode • Vultr
# ==============================================================================

set -e

echo "=========================================================="
echo "⚡ Starting AegisScan Cloud VPS Production Deployment"
echo "=========================================================="

# 1. Update system packages
echo "[*] Updating system packages..."
sudo apt-get update -y && sudo apt-get upgrade -y

# 2. Install Nmap, Python3, and Git
echo "[*] Installing Nmap and core networking tools..."
sudo apt-get install -y nmap python3 python3-pip python3-venv git curl nginx certbot python3-certbot-nginx

# 3. Create virtual environment & install requirements
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt gunicorn

# 4. Create Systemd Service for 24/7 background uptime
echo "[*] Creating systemd service (aegisscan.service)..."
APP_DIR=$(pwd)
USER_NAME=$(whoami)

sudo bash -c "cat > /etc/systemd/system/aegisscan.service" <<EOF
[Unit]
Description=AegisScan Production Gunicorn Server
After=network.target

[Service]
User=$USER_NAME
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 3 --threads 4 --timeout 180 web_app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 5. Reload and start systemd service
sudo systemctl daemon-reload
sudo systemctl enable aegisscan
sudo systemctl restart aegisscan

echo "=========================================================="
echo "✅ AegisScan service is running locally on port 5000!"
echo "Status check: sudo systemctl status aegisscan"
echo "=========================================================="
echo ""
echo "👉 NEXT STEP (Configure Nginx & Free HTTPS Domain):"
echo "1. Point your domain DNS (A record) to this VPS IP address."
echo "2. Edit /etc/nginx/sites-available/aegisscan and run:"
echo "   sudo certbot --nginx -d yourdomain.com"
echo "=========================================================="
