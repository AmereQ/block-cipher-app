import csv
import string
import tkinter as tk
import random
from tkinter import ttk, messagebox, filedialog
import base64
import time
import os

from ciphers.aes_cipher import generate_aes_key, encrypt_aes_ecb, decrypt_aes_ecb
from ciphers.twofish_cipher import generate_twofish_key, encrypt_twofish_ecb, decrypt_twofish_ecb
from ciphers.serpent_cipher import generate_serpent_key, encrypt_serpent_ecb, decrypt_serpent_ecb

current_key = None
wiadomosc_bin = None

# Funkcja zapisu czasu do pliku
def zapisz_czas(operacja, algorytm, czas_ms, dlugosc_we=0, dlugosc_szyf=0):
    naglowki = ["Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"]
    wiersz = {
        "Operacja": operacja,
        "Algorytm": algorytm,
        "Czas (ms)": round(czas_ms, 3),
        "Długość wejścia (B)": dlugosc_we,
        "Długość szyfrogramu (B)": dlugosc_szyf
    }
    plik = "czasy.csv"
    nowy = not os.path.exists(plik)
    try:
        with open(plik, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=naglowki)
            if nowy:
                writer.writeheader()
            writer.writerow(wiersz)
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zapisać czasu do pliku:\n{e}")

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
    dane_bin = tekst.encode("utf-8")
    if wiadomosc_bin:
        dane_bin = wiadomosc_bin
    if not tekst:
        messagebox.showwarning("Brak danych", "Wpisz wiadomość do zaszyfrowania.")
        return
    try:
        start_time = time.perf_counter()
        use_padding_flag = use_padding.get()
        if alg == "AES":
            ciphertext = encrypt_aes_ecb(tekst, current_key, use_padding=use_padding_flag)
        elif alg == "Twofish":
            ciphertext = encrypt_twofish_ecb(tekst, current_key, use_padding=use_padding_flag)
        elif alg == "Serpent":
            ciphertext = encrypt_serpent_ecb(tekst, current_key, use_padding=use_padding_flag)
        else:
            raise ValueError("Nieznany algorytm")
        label_dlugosc_wiadomosci.config(text=f"Długość wiadomości (binarna): {len(dane_bin)} bajtów")
        label_dlugosc_szyfrowania.config(text=f"Długość szyfrogramu: {len(ciphertext)} bajtów")
        end_time = time.perf_counter()
        czas_szyfrowania = (end_time - start_time) * 1000  # ms
        wynik_var.set(base64.b64encode(ciphertext).decode())
        label_czas_szyfrowania.config(text=f"Czas szyfrowania: {czas_szyfrowania:.3f} ms")

        zapisz_czas("szyfrowanie", alg, czas_szyfrowania, dlugosc_we=len(dane_bin), dlugosc_szyf=len(ciphertext))
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
        use_padding_flag = use_padding.get()
        start_time = time.perf_counter()

        if alg == "AES":
            plaintext = decrypt_aes_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        elif alg == "Twofish":
            plaintext = decrypt_twofish_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        elif alg == "Serpent":
            plaintext = decrypt_serpent_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        else:
            raise ValueError("Nieznany algorytm")

        end_time = time.perf_counter()
        czas_deszyfrowania = (end_time - start_time) * 1000  # ms

        wynik_odszyfrowany_var.set(plaintext)
        label_czas_deszyfrowania.config(text=f"Czas deszyfrowania: {czas_deszyfrowania:.3f} ms")

        zapisz_czas("deszyfrowanie", alg, czas_deszyfrowania, dlugosc_we=len(ciphertext), dlugosc_szyf=len(plaintext))
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się odszyfrować:\n{e}")

# Funkcja do wyświetlania tabeli
def pokaz_tabele():
    csv_file = "czasy.csv"
    if not os.path.exists(csv_file):
        messagebox.showinfo("Brak danych", "Plik z czasami nie istnieje.")
        return

    tabela_okno = tk.Toplevel(root)
    tabela_okno.title("Tabela czasów operacji")
    tabela_okno.geometry("900x300")

    tree = ttk.Treeview(tabela_okno, columns=("Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"), show="headings")
    for col in ("Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"):
        tree.heading(col, text=col)
        tree.column(col, width=100)
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    try:
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) == 5:
                    tree.insert("", tk.END, values=row)
    except Exception as e:
        messagebox.showerror("Błąd", f"Błąd wczytywania CSV:\n{e}")

    def usun_wybrany():
        zaznaczone = tree.selection()
        if not zaznaczone:
            messagebox.showinfo("Brak wyboru", "Wybierz wiersz do usunięcia.")
            return

        for item in zaznaczone:
            wartosci = tree.item(item)["values"]
            tree.delete(item)

            # Usuń z pliku CSV
            with open(csv_file, newline='', encoding='utf-8') as f:
                rows = list(csv.reader(f))
            with open(csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(rows[0])  # nagłówek
                for r in rows[1:]:
                    if r != list(map(str, wartosci)):
                        writer.writerow(r)

    def usun_wszystkie():
        if messagebox.askyesno("Potwierdzenie", "Czy na pewno chcesz usunąć wszystkie dane?"):
            for item in tree.get_children():
                tree.delete(item)
            with open(csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"])

    def eksportuj_csv():
        nowa_sciezka = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if nowa_sciezka:
            try:
                with open(nowa_sciezka, "w", newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Operacja", "Algorytm", "Rozmiar", "Padding", "Czas (ms)"])
                    for row_id in tree.get_children():
                        writer.writerow(tree.item(row_id)["values"])
                messagebox.showinfo("Eksport zakończony", f"Dane zapisane do {nowa_sciezka}")
            except Exception as e:
                messagebox.showerror("Błąd eksportu", str(e))
    # Przyciski
    przyciski_frame = tk.Frame(tabela_okno)
    przyciski_frame.pack(pady=5)

    tk.Button(przyciski_frame, text="Usuń wybrany wiersz", command=usun_wybrany).grid(row=0, column=0, padx=5)
    tk.Button(przyciski_frame, text="Usuń wszystkie dane", command=usun_wszystkie).grid(row=0, column=1, padx=5)
    tk.Button(przyciski_frame, text="Eksportuj do CSV", command=eksportuj_csv).grid(row=0, column=2, padx=5)
def losowa_dlugosc():
    global wiadomosc_bin
    wybor = combo_dane.get()
    rozmiary = {
        "16B": 16,
        "32B": 32,
        "64B": 64,
        "128B": 128,
        "1KB": 1024,
        "10KB": 10240,
    }

    liczba = rozmiary.get(wybor)
    if liczba is None:
        messagebox.showerror("Błąd", "Wybierz prawidłową długość danych.")
        return

    # Generuj losowy tekst ASCII o zadanej długości
    znaki = string.ascii_letters + string.digits + string.punctuation
    losowy_tekst = ''.join(random.choices(znaki, k=liczba))

    # Ustawiamy jako wiadomość
    wynik_losowy.set(losowy_tekst)
    wiadomosc_bin = losowy_tekst.encode("utf-8")
# --- GUI ---
root = tk.Tk()
root.title("Szyfrowanie blokowe – AES / Twofish / Serpent")
root.geometry("600x600")
frame_wiadomosc = tk.Frame(root)
frame_wiadomosc.pack(pady=5)
tk.Label(frame_wiadomosc, text="Wiadomość:").pack()
wynik_losowy = tk.StringVar()
entry_wiadomosc = tk.Entry(frame_wiadomosc,textvariable=wynik_losowy, width=60)
entry_wiadomosc.pack(side=tk.LEFT, padx=5)
btn_czysc = tk.Button(frame_wiadomosc, text="Wyczyść", command=lambda: entry_wiadomosc.delete(0, tk.END))
btn_czysc.pack(side=tk.LEFT)
frame_losowa = tk.Frame(root)
frame_losowa.pack(pady=5)
tk.Label(frame_losowa, text="Losowa treść:").pack()
combo_dane = ttk.Combobox(frame_losowa, values=["16B", "32B", "64B", "128B", "1KB", "10KB"], state="readonly")
combo_dane.current(0)
combo_dane.pack(side=tk.LEFT)
tk.Button(frame_losowa, text="Generuj", command=losowa_dlugosc).pack(side=tk.LEFT,padx=5)

tk.Label(root, text="Wybierz algorytm szyfrowania:").pack()
combo_algorytm = ttk.Combobox(root, values=["AES", "Twofish", "Serpent"], state="readonly")
combo_algorytm.current(0)
combo_algorytm.pack()

tk.Label(root, text="Wybierz długość klucza (bit):").pack()
combo_klucz = ttk.Combobox(root, values=["128", "192", "256"], state="readonly")
combo_klucz.current(0)
combo_klucz.pack()

tk.Button(root, text="Wygeneruj klucz", command=wygeneruj_klucz).pack(pady=5)
label_klucz = tk.Label(root, text="Klucz: brak", fg="gray")
label_klucz.pack()

use_padding = tk.BooleanVar(value=True)
tk.Checkbutton(root, text="Użyj paddingu (zalecane)", variable=use_padding).pack()
tk.Button(root, text="Szyfruj", command=szyfruj).pack(pady=5)

label_czas_szyfrowania = tk.Label(root, text="Czas szyfrowania: brak", fg="blue")
label_czas_szyfrowania.pack()

tk.Label(root, text="Szyfrogram (base64):").pack()
wynik_var = tk.StringVar()
tk.Entry(root, textvariable=wynik_var, width=60).pack()

tk.Button(root, text="Deszyfruj", command=deszyfruj).pack(pady=5)
label_czas_deszyfrowania = tk.Label(root, text="Czas deszyfrowania: brak", fg="blue")
label_czas_deszyfrowania.pack()

tk.Label(root, text="Odszyfrowana wiadomość:").pack()
wynik_odszyfrowany_var = tk.StringVar()
tk.Entry(root, textvariable=wynik_odszyfrowany_var, width=60).pack()
tk.Button(root, text="Pokaż tabelę czasów", command=pokaz_tabele).pack(pady=5)
label_dlugosc_wiadomosci = tk.Label(root, text="", fg="gray")
label_dlugosc_wiadomosci.pack()
label_dlugosc_szyfrowania = tk.Label(root, text="", fg="gray")
label_dlugosc_szyfrowania.pack()
root.mainloop()
