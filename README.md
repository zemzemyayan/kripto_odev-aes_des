# kripto_odevi - 

## Kurulum
python -m venv venv
source venv/bin/activate
pip install pycryptodome flask

## Çalıştırma
1) Sunucuyu aç:
   python server/server.py

2) Konsol istemcisi ile test:
   python cli_client/client.py

3) Web istemcisi (opsiyonel):
   cd web_client
   FLASK_APP=app.py flask run --host=127.0.0.1 --port=8000
   Tarayıcı: http://127.0.0.1:8000

## Wireshark
- Sunucu TCP portu 5000 üzerinde çalışır. Wireshark'ta filtre olarak `tcp.port == 5000` yaz.
- Gönderilen paketlerin payload'ı trafiğe açık hex olarak gözükür, fakat AES/DES ile şifreliyse okunaklı metin görünmez.

