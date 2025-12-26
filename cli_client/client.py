# cli_client/client.py
import socket
import binascii
import sys
import json
import os
import sys 

# Proje kök dizinini Python path'e ekler
# Böylece crypto_lib, utils gibi klasörlerden import yapılabilir
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from crypto_lib.lib_crypto import (
    aes_encrypt_lib,
    des_encrypt_lib,
    rsa_encrypt,
)

# HOST = 127.0.0.1:
# Server 0.0.0.0 dinler → "her yerden bağlantı kabul et"
# Client bağlanırken SOMUT bir adres vermek zorunda → localhost
HOST = "127.0.0.1"
PORT = 5000


# send_message:
# Şifreleme YAPMAZ
# Sadece Python dict → JSON → bytes dönüşümü yapar
def send_message(message_dict):
    # json.dumps → dict → string
    # encode("utf8") → string → bytes
    msg = json.dumps(message_dict).encode("utf8")
    return msg


def main():
    print("Algoritma seçin: AES / DES / RSA")
    alg = input("Alg: ").strip().upper()

    print("Mod seçin: lib / manual (AES sadece lib, DES her ikisi)")
    mode = input("Mode: ").strip().lower()

    # Kullanıcıdan alınan mesaj
    # encode("utf8") → string → bytes
    message = input("Gönderilecek mesaj: ").encode("utf8")

    # payload:
    # ŞİFRELİ HALDE GÖNDERİLECEK VERİ
    payload = None

    # key_info:
    # Anahtar bilgisi JSON içinde gönderilecek
    key_info = {}

    # -------------------------------------------------------------
    # AES
    # -------------------------------------------------------------
    if alg == "AES":
        if mode != "lib":
            print("Manual AES bu projede yok. Lütfen 'lib' seçin.")
            sys.exit(1)

        # AES-128 → 16 byte key gerekir
        # Eğitim/demo amaçlı SABİT key
        key = b"\x00" * 16

        # message (plain) → ciphertext
        ciphertext = aes_encrypt_lib(key, message)

        # payload = şifreli veri
        payload = ciphertext

        # key_info içine hex formatta key koyulur
        key_info = {"key": key.hex()}

    # -------------------------------------------------------------
    # DES
    # -------------------------------------------------------------
    elif alg == "DES":
        # b"" → bytes literal
        # DES anahtarı 8 byte olmak zorunda
        key = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        if mode == "lib":
            ciphertext = des_encrypt_lib(key, message)
            payload = ciphertext
            key_info = {"key": key.hex()}

        else:
            # Manuel DES sadece 8 byte blok çalışır
            try:
                from manual_crypto.manual_des import des_encrypt_block
            except Exception:
                print("manual_des bulunamadı veya fonksiyon eksik.")
                sys.exit(1)

            if len(message) != 8:
                print("Manual DES için mesaj 8 byte olmalıdır. Ör: '12345678'")
                sys.exit(1)

            ciphertext = des_encrypt_block(message, key)
            payload = ciphertext
            key_info = {"key": key.hex()}

    # -------------------------------------------------------------
    # RSA
    # -------------------------------------------------------------
    elif alg == "RSA":
        try:
            # Sunucunun public key'i
            pub = open("server_pub.pem", "rb").read()
        except:
            print("server_pub.pem bulunamadı. Sunucu ilk çalıştırmayı yapmamış olabilir.")
            sys.exit(1)

        # RSA encrypt: public key ile şifreleme
        ciphertext = rsa_encrypt(pub, message)
        payload = ciphertext

    else:
        print("Bilinmeyen algoritma.")
        sys.exit(1)

    # -----------------------------
    # JSON paket hazırlanır
    # Bu yapı Wireshark'ta gördüğün JSON'dur
    # -----------------------------
    msg_dict = {
        "alg": alg,                 # hangi algoritma
        "mode": mode,               # lib / manual
        "payload": payload.hex(),   # ŞİFRELİ VERİ
        "key_info": key_info,       # anahtar bilgisi
    }

    # JSON → bytes
    data = send_message(msg_dict)

    # -----------------------------
    # TCP bağlantısı
    # -----------------------------
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Server'a bağlan
    s.connect((HOST, PORT))

    # TÜM byte'ları gönder
    s.sendall(data)

    s.close()

    print("Mesaj gönderildi.")

    # payload.hex():
    # Şifreli verinin insan tarafından okunabilir hali
    print("Şifreli mesaj (hex):", payload.hex())


if __name__ == "__main__":
    main()
