# server/server.py
import socket
import threading
import binascii
import os
import sys 

# Proje kök dizinini (kripto_odevi) Python path'e ekler.
# Böylece utils, crypto_lib gibi klasörlerden import yapılabilir.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from utils.protocol import unpack_message
from crypto_lib.lib_crypto import aes_decrypt_lib, des_decrypt_lib, rsa_decrypt

HOST = '0.0.0.0'
PORT = 5000

# handle_client:
# Sunucuya bağlanan HER BİR istemci için çağrılan fonksiyondur.
# Aynı anda birden fazla istemci bağlanabilsin diye thread içinde çalıştırılır.
def handle_client(conn, addr):
    print(f"[+] Yeni istemci: {addr}")
    try:
        # conn.recv(65536):
        # TCP soketten gelen veriyi okur.
        # 65536 = maksimum okunacak byte sayısı (64 KB)
        # TCP paket paket gelir ama burada uygulama seviyesinde "okuma limiti" belirlenir.
        data = conn.recv(65536)

        # unpack_message:
        # Client tarafından gönderilen JSON bytes → Python dict'e çevrilir.
        # JSON, client tarafında hazırlanıp TCP üzerinden gönderilmiştir.
        msg = unpack_message(data)

        # JSON bozuksa veya parse edilemezse None döner
        if not msg:
            print("Geçersiz JSON.")
            conn.close()
            return

        # JSON içinden alanlar okunur
        alg = msg.get("alg")          # AES / DES / RSA bilgisi
        mode = msg.get("mode")        # lib / manual
        payload_hex = msg.get("payload")  # ŞİFRELİ mesaj (hex string)
        keyinfo = msg.get("key_info", {}) # Anahtar bilgileri

        print(f"[.] Alg: {alg}, Mode: {mode}")

        # binascii.unhexlify:
        # payload_hex string → gerçek byte dizisine çevrilir
        # Yani ağdan gelen "3baf6b..." → b'\x3b\xaf...'
        payload = binascii.unhexlify(payload_hex)

        # ---------------- AES ----------------
        if alg == "AES":
            if mode == "lib":
                # key bilgisi JSON içinden alınır
                key_hex = keyinfo.get("key")  # hex string anahtar

                # Anahtar yoksa hata
                if not key_hex:
                    print("AES lib: key bilgisi yok.")
                else:
                    # hex anahtar → byte anahtar
                    key = binascii.unhexlify(key_hex)

                    try:
                        # AES ile şifreli payload çözülür
                        pt = aes_decrypt_lib(key, payload)

                        # pt.decode:
                        # byte → okunabilir string (utf8)
                        # errors='replace': bozuk byte varsa hata vermesin
                        print("[DECRYPTED AES(lib)]:", pt.decode('utf8', errors='replace'))
                    except Exception as e:
                        print("AES lib decrypt hata:", e)

        # ---------------- DES ----------------
        elif alg == "DES":
            if mode == "lib":
                key_hex = keyinfo.get("key")
                if not key_hex:
                    print("DES lib: key bilgisi yok.")
                else:
                    key = binascii.unhexlify(key_hex)
                    try:
                        pt = des_decrypt_lib(key, payload)
                        print("[DECRYPTED DES(lib)]:", pt.decode('utf8', errors='replace'))
                    except Exception as e:
                        print("DES lib decrypt hata:", e)
            else:
                # Manuel DES sadece seçilirse import edilir (lazy import)
                try:
                    from manual_crypto.manual_des import des_decrypt_block as manual_des_decrypt_block
                except Exception:
                    print("Manual DES modülü yok veya fonksiyon bulunamadı.")
                    conn.close(); return

                # Manuel DES sadece 8 byte blokla çalışır
                if len(payload) != 8:
                    print("Manual DES demo: payload tek 8 byte blok olmalı.")
                else:
                    try:
                        # JSON içinden anahtar alınır
                        key_hex = keyinfo.get("key")

                        # Eğer key yoksa varsayılan DES anahtarı kullanılır
                        key = binascii.unhexlify(key_hex) if key_hex else b'\x01\x02\x03\x04\x05\x06\x07\x08'

                        # Şifreli 8 byte → düz metin
                        pt = manual_des_decrypt_block(payload, key)

                        # pt.hex():
                        # Manuel DES sonucu byte ama decode etmiyoruz
                        # hex olarak gösteriyoruz
                        print("[DECRYPTED DES(manual)]:", pt.hex())
                    except Exception as e:
                        print("Manual DES decrypt hata:", e)

        # ---------------- RSA ----------------
        elif alg == "RSA":
            # RSA private key dosyası var mı kontrol edilir
            if not os.path.exists("server_private.pem"):
                print("RSA private key bulunamadı.")
            else:
                # private key binary olarak okunur
                priv_pem = open("server_private.pem","rb").read()

                try:
                    # RSA decrypt:
                    # payload = şifreli veri
                    # priv_pem = sunucuya ait private key
                    pt = rsa_decrypt(priv_pem, payload)
                    print("[DECRYPTED RSA]:", pt.decode('utf8', errors='replace'))
                except Exception as e:
                    print("RSA decrypt hata:", e)
        else:
            print("Bilinmeyen algoritma.")

    except Exception as e:
        print("connection error:", e)
    finally:
        conn.close()
        print("[-] Bağlantı kapandı:", addr)


def start_server():
    # RSA private key yoksa ilk çalıştırmada oluşturulur
    if not os.path.exists("server_private.pem"):
        from crypto_lib.lib_crypto import rsa_generate

        # pub = public key, priv = private key
        pub, priv = rsa_generate()

        # Dosyalara yazılır
        with open("server_pub.pem","wb") as f: f.write(pub)
        with open("server_private.pem","wb") as f: f.write(priv)

        print("[+] RSA anahtarları oluşturuldu: server_pub.pem / server_private.pem")

    # TCP socket oluşturulur
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # IP ve port bağlanır
    s.bind((HOST, PORT))

    # Aynı anda max 5 bağlantı kuyruğu
    s.listen(5)

    print(f"[+] Sunucu dinleniyor {HOST}:{PORT}")

    while True:
        # accept:
        # Yeni bir istemci bağlanana kadar BEKLER
        conn, addr = s.accept()

        # Her istemci için ayrı thread
        t = threading.Thread(target=handle_client, args=(conn, addr))

        # Thread çalıştırılır
        t.start()

if __name__ == "__main__":
    start_server()
