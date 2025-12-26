# web_client/app.py
import os
import sys 

# Proje kökü path'e eklenir
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from flask import Flask, render_template, request, redirect, url_for, flash
import binascii
import socket

from utils.protocol import pack_message
from crypto_lib.lib_crypto import aes_encrypt_lib, des_encrypt_lib, rsa_encrypt

app = Flask(__name__)

# Flask flash mesajları için gizli anahtar
app.secret_key = "demo-secret"

SERVER = '127.0.0.1'
PORT = 5000


# JSON objesini TCP üzerinden sunucuya gönderir
def send_json_to_server(obj):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER, PORT))
    s.sendall(pack_message(obj))
    s.close()


# "/" adresi
# GET → sayfa göster
# POST → form gönderildi
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        alg = request.form["alg"]
        mode = request.form["mode"]

        # HTML formundan gelen metin → bytes
        text = request.form["message"].encode("utf8")

        # Başta boş
        key_info = {}

        # payload boş byte dizisi
        payload = b""

        # =======================================================
        # AES
        # =======================================================
        if alg == "AES":
            if mode != "lib":
                flash("Manual AES bu projede yok.")
                return redirect(url_for("index"))

            key = b"\x00" * 16
            payload = aes_encrypt_lib(key, text)
            key_info["key"] = key.hex()

        # =======================================================
        # DES
        # =======================================================
        elif alg == "DES":
            key = b"\x01\x02\x03\x04\x05\x06\x07\x08"

            if mode == "lib":
                payload = des_encrypt_lib(key, text)
                key_info["key"] = key.hex()
            else:
                if len(text) != 8:
                    flash("Manual DES için mesaj 8 byte olmalı.")
                    return redirect(url_for("index"))

                try:
                    from manual_crypto.manual_des import des_encrypt_block
                except Exception:
                    flash("manual_des.py bulunamadı.")
                    return redirect(url_for("index"))

                payload = des_encrypt_block(text, key)
                key_info["key"] = key.hex()

        # =======================================================
        # RSA
        # =======================================================
        elif alg == "RSA":
            try:
                pub = open("server_pub.pem", "rb").read()
            except:
                flash("Önce sunucuyu çalıştırın.")
                return redirect(url_for("index"))

            payload = rsa_encrypt(pub, text)

        else:
            flash("Geçersiz algoritma.")
            return redirect(url_for("index"))

        # JSON objesi oluşturulur
        obj = {
            "alg": alg,
            "mode": mode,
            "payload": payload.hex(),
            "key_info": key_info,
        }

        send_json_to_server(obj)
        flash("Mesaj sunucuya gönderildi.")
        return redirect(url_for("index"))

    return render_template("index.html")


if __name__ == "__main__":
    # Web arayüz 8000 portunda
    app.run(host="127.0.0.1", port=8000, debug=True)


# C:/Users/HP/Desktop/kripto_odevi/venv/Scripts/activate.bat