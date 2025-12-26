# crypto_lib/lib_crypto.py
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# AES 128 CBC (kütüphane ile)
def aes_encrypt_lib(key16: bytes, plaintext: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key16, AES.MODE_CBC, iv)
    # PKCS7 pad
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len])*pad_len
    ct = cipher.encrypt(padded)
    return iv + ct  # başına IV ekliyoruz

def aes_decrypt_lib(key16: bytes, data: bytes):
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key16, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad_len = pt[-1]
    return pt[:-pad_len]

# DES (pycryptodome) - DES.MODE_CBC
def des_encrypt_lib(key8: bytes, plaintext: bytes):
    iv = get_random_bytes(8)
    cipher = DES.new(key8, DES.MODE_CBC, iv)
    pad_len = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([pad_len])*pad_len
    ct = cipher.encrypt(padded)
    return iv + ct

def des_decrypt_lib(key8: bytes, data: bytes):
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(key8, DES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad_len = pt[-1]
    return pt[:-pad_len]

# RSA key generation + encrypt/decrypt with OAEP
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return pub, priv

def rsa_encrypt(pubkey_pem: bytes, message: bytes):
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def rsa_decrypt(privkey_pem: bytes, ciphertext: bytes):
    key = RSA.import_key(privkey_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)
