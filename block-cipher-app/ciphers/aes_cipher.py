# ciphers/aes_cipher.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_aes_key(bits=128):
    if bits not in [128, 192, 256]:
        raise ValueError("Długość klucza AES musi być 128, 192 lub 256 bitów.")
    return get_random_bytes(bits // 8)

def encrypt_aes_ecb(plaintext: str, key: bytes, use_padding=True) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded=plaintext.encode()
    if use_padding:
        padded = pad(padded, AES.block_size)
    elif len(padded) % 16 != 0:
        raise ValueError("Długość danych musi być wielokrotnością 16 bajtów, gdy padding jest wyłączony.")
    ciphertext = cipher.encrypt(padded)
    return ciphertext

def decrypt_aes_ecb(ciphertext: bytes, key: bytes, use_padding=True) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    if use_padding:
        decrypted = unpad(decrypted, AES.block_size)
    return decrypted.decode()
