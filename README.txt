PYTHON PAKET KURULUMLARI
------------------------
pip install requests
pip install beautifulsoup4
pip install python-telegram-bot
pip install pyngrok
pip install flask
pip install colorama
pip install pyopenssl
pip install cryptography

NGROK KURULUMU (Linux)
----------------------
wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip -O ngrok.zip
unzip ngrok.zip
chmod +x ngrok
sudo mv ngrok /usr/local/bin/
ngrok authtoken 2MZRE7FsDM53KMxKyyVrPnEkXdZ_3NdnwopRAQ9ew6yt6LNYZ
rm ngrok.zip

TERMUX ÖZEL KURULUMLAR
----------------------
pkg install python -y
pkg install openssl -y
pkg install libxml2 -y
pkg install libxslt -y

OPSİYONEL GÜNCELLEMELER
-----------------------
pip install --upgrade pip
python -m pip install --upgrade setuptools wheel
