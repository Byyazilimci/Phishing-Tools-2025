#!/bin/bash

# ===========================================
# PYTHON PACKAGE INSTALLATIONS
# ===========================================
echo -e "\033[1;34m\n\n\n\nInstalling Python dependencies...\033[0m"
pip install requests                # HTTP requests
pip install beautifulsoup4          # HTML parsing
pip install python-telegram-bot     # Telegram Bot API
pip install pyngrok                 # Ngrok integration
pip install flask                   # Web server
pip install colorama                # Colored terminal output
pip install pyopenssl               # SSL certificates
pip install cryptography            # Encryption operations


# ===========================================
# NGROK INSTALLATION (Linux)
# ===========================================
echo -e "\033[1;34m\n\n\n\nSetting up Ngrok tunnel...\033[0m"
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok.zip
unzip ngrok.zip
chmod +x ngrok
sudo mv ngrok /usr/local/bin/
ngrok authtoken 2MZRE7FsDM53KMxKyyVrPnEkXdZ_3NdnwopRAQ9ew6yt6LNYZ
rm ngrok.zip  # Cleanup


# ===========================================
# TERMUX-SPECIFIC INSTALLATIONS
# ===========================================
echo -e "\033[1;34m\n\n\n\nInstalling Termux packages...\033[0m"
pkg install python -y               # Python installation
pkg install openssl -y              # SSL support
pkg install libxml2 -y              # XML parsing
pkg install libxslt -y              # XSLT transformations


# ===========================================
# OPTIONAL UPDATES
# ===========================================
echo -e "\033[1;34m\n\n\n\nPerforming optional updates...\033[0m"
pip install --upgrade pip           # Pip upgrade
python -m pip install --upgrade setuptools wheel


# ===========================================
# VERIFICATION
# ===========================================
echo -e "\033[1;32m\n\n\n\nInstallation complete!\033[0m"
echo -e "\033[1;33mVerify the installation with:\033[0m"
echo -e "python --version"
echo -e "ngrok --version"
echo -e "pip list"
