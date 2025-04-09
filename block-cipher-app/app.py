import tkinter as tk
from tkinter import ttk, messagebox
import base64

from ciphers.aes_cipher import generate_aes_key, encrypt_aes_ecb, decrypt_aes_ecb
from ciphers.twofish_cipher import generate_twofish_key, encrypt_twofish_ecb, decrypt_twofish_ecb
from ciphers.serpent_cipher import generate_serpent_key, encrypt_serpent_ecb, decrypt_serpent_ecb

current_key = None

def wygeneruj_klucz():
    global current_key
    alg = combo_algorytm.get()
    bits = int(combo_klucz.get())

    try:
        if alg == "AES":
            current_key = generate_aes_key(bits)
        elif alg == "Twofish":
            current_key = generate_twofish_key(bits)
        elif alg == "Serpent":
            current_key = generate_serpent_key(bits)
        else:
            messagebox.showwarning("Błąd", f"Nieznany algorytm: {alg}")
            return
        label_klucz.config(text=f"Klucz ({bits} bit): {current_key.hex()}")
    except Exception as e:
        messagebox.showerror("Błąd", str(e))

def szyfruj():
    global current_key
    alg = combo_algorytm.get()
    if not current_key:
        messagebox.showwarning("Brak klucza", "Najpierw wygeneruj klucz!")
        return
    tekst = entry_wiadomosc.get()
    if not tekst:
        messagebox.showwarning("Brak danych", "Wpisz wiadomość do zaszyfrowania.")
        return
    try:
        if alg == "AES":
            ciphertext = encrypt_aes_ecb(tekst, current_key)
        elif alg == "Twofish":
            ciphertext = encrypt_twofish_ecb(tekst, current_key)
        elif alg == "Serpent":
            ciphertext = encrypt_serpent_ecb(tekst, current_key)
        else:
            raise ValueError("Nieznany algorytm")
        wynik_var.set(base64.b64encode(ciphertext).decode())
    except Exception as e:
        messagebox.showerror("Błąd", f"Błąd szyfrowania: {e}")

def deszyfruj():
    global current_key
    alg = combo_algorytm.get()
    if not current_key:
        messagebox.showwarning("Brak klucza", "Najpierw wygeneruj klucz!")
        return
    try:
        ciphertext = base64.b64decode(wynik_var.get())
        if alg == "AES":
            plaintext = decrypt_aes_ecb(ciphertext, current_key)
        elif alg == "Twofish":
            plaintext = decrypt_twofish_ecb(ciphertext, current_key)
        elif alg == "Serpent":
            plaintext = decrypt_serpent_ecb(ciphertext, current_key)
        else:
            raise ValueError("Nieznany algorytm")
        wynik_odszyfrowany_var.set(plaintext)
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się odszyfrować:\n{e}")

# --- GUI ---
root = tk.Tk()
root.title("Szyfrowanie blokowe – AES / Twofish / Serpent")
root.geometry("600x450")

tk.Label(root, text="Wiadomość:").pack()
entry_wiadomosc = tk.Entry(root, width=60)
entry_wiadomosc.pack(pady=5)

tk.Label(root, text="Wybierz algorytm szyfrowania:").pack()
combo_algorytm = ttk.Combobox(root, values=["AES", "Twofish", "Serpent"])
combo_algorytm.current(0)
combo_algorytm.pack()

tk.Label(root, text="Wybierz długość klucza (bit):").pack()
combo_klucz = ttk.Combobox(root, values=["128", "192", "256"])
combo_klucz.current(0)
combo_klucz.pack()

tk.Button(root, text="Wygeneruj klucz", command=wygeneruj_klucz).pack(pady=5)
label_klucz = tk.Label(root, text="Klucz: brak", fg="gray")
label_klucz.pack()

tk.Button(root, text="Szyfruj", command=szyfruj).pack(pady=5)

tk.Label(root, text="Szyfrogram (base64):").pack()
wynik_var = tk.StringVar()
tk.Entry(root, textvariable=wynik_var, width=60).pack()

tk.Button(root, text="Deszyfruj", command=deszyfruj).pack(pady=5)

tk.Label(root, text="Odszyfrowana wiadomość:").pack()
wynik_odszyfrowany_var = tk.StringVar()
tk.Entry(root, textvariable=wynik_odszyfrowany_var, width=60).pack()

root.mainloop()
