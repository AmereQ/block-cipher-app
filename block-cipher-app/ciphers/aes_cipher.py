# ciphers/aes_cipher.py

from Crypto.Cipher import AES  # klasa implementująca szyfr AES
from Crypto.Util.Padding import pad, unpad  # funkcje dodawania/usuwania paddingu PKCS#7
from Crypto.Random import get_random_bytes  # kryptograficznie bezpieczne losowe bajty


def generate_aes_key(bits=128):  # generuje klucz AES (domyślnie 128 bitów)
    if bits not in [128, 192, 256]:  # sprawdzenie, czy długość klucza jest dozwolona
        raise ValueError("Długość klucza AES musi być 128, 192 lub 256 bitów.")  # wyjątek dla niepoprawnej długości klucza
    return get_random_bytes(bits // 8)  # zwraca losowy klucz o żądanej długości w bajtach


def encrypt_aes_ecb(plaintext: str, key: bytes, use_padding=True) -> bytes:  # szyfruje tekst jawny w trybie AES‑ECB
    cipher = AES.new(key, AES.MODE_ECB)  # tworzy obiekt szyfru AES w trybie ECB
    padded=plaintext.encode()  # zamienia str na bajty (UTF‑8)
    if use_padding:  # jeśli padding jest włączony
        padded = pad(padded, AES.block_size)  # dodaje padding PKCS#7 do wielokrotności 16 bajtów
    elif len(padded) % 16 != 0:  # gdy padding wyłączony, długość musi być wielokrotnością 16 bajtów
        raise ValueError("Długość danych musi być wielokrotnością 16 bajtów, gdy padding jest wyłączony.")  # wyjątek dla niepoprawnej długości
    ciphertext = cipher.encrypt(padded)  # szyfruje dane
    return ciphertext  # zwraca szyfrogram w postaci bajtów


def decrypt_aes_ecb(ciphertext: bytes, key: bytes, use_padding=True) -> str:  # odszyfrowuje szyfrogram w trybie AES‑ECB
    cipher = AES.new(key, AES.MODE_ECB)  # tworzy obiekt szyfru AES w trybie ECB
    decrypted = cipher.decrypt(ciphertext)  # odszyfruje dane
    if use_padding:  # jeśli dane zawierają padding
        decrypted = unpad(decrypted, AES.block_size)  # usuwa padding PKCS#7
    return decrypted.decode()  # konwertuje bajty na str i zwraca tekst jawny
