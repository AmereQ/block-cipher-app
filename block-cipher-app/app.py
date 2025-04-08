import tkinter as tk
from tkinter import ttk

# Funkcja pod przycisk (na razie tylko placeholder)
def szyfruj():
    tekst = entry_wiadomosc.get()
    algorytm = combo_algorytm.get()
    wynik_var.set(f"Szyfrowanie {algorytm}: {tekst}")

# Tworzenie głównego okna
root = tk.Tk()
root.title("Szyfrowanie danych – AES, Twofish, Serpent")
root.geometry("500x300")

# Etykieta i pole do wpisywania wiadomości
tk.Label(root, text="Wiadomość do zaszyfrowania:").pack(pady=5)
entry_wiadomosc = tk.Entry(root, width=50)
entry_wiadomosc.pack()

# Wybór algorytmu
tk.Label(root, text="Wybierz algorytm:").pack(pady=5)
combo_algorytm = ttk.Combobox(root, values=["AES", "Twofish", "Serpent"])
combo_algorytm.current(0)
combo_algorytm.pack()

# Przycisk szyfrowania
tk.Button(root, text="Szyfruj", command=szyfruj).pack(pady=10)

# Wynik szyfrowania
wynik_var = tk.StringVar()
tk.Label(root, textvariable=wynik_var, fg="blue").pack(pady=10)

# Uruchomienie GUI
root.mainloop()
