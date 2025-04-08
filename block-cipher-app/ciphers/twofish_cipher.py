# ciphers/twofish_cipher.py

from twofish import Twofish
from Crypto.Util.Padding import pad, unpad

def generate_twofish_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza Twofish musi być 128, 192 lub 256 bitów.")
    return bytes([0] * (bits // 8))  # dla uproszczenia — zero-klucz (możesz zmienić na losowy)

def encrypt_twofish_ecb(plaintext: str, key: bytes) -> bytes:
    tf = Twofish(key)
    padded = pad(plaintext.encode(), 16)  # blok 16 bajtów
    encrypted = b""
    for i in range(0, len(padded), 16):
        encrypted += tf.encrypt(padded[i:i+16])
    return encrypted

def decrypt_twofish_ecb(ciphertext: bytes, key: bytes) -> str:
    tf = Twofish(key)
    decrypted = b""
    for i in range(0, len(ciphertext), 16):
        decrypted += tf.decrypt(ciphertext[i:i+16])
    return unpad(decrypted, 16).decode()
