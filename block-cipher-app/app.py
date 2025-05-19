# Importowanie niezbędnych bibliotek
import csv
import string
import tkinter as tk
import random
from tkinter import ttk, messagebox, filedialog
import base64
import time
import os
# Importowanie funkcji szyfrowania i deszyfrowania dla AES, Twofish i Serpent
from ciphers.aes_cipher import generate_aes_key, encrypt_aes_ecb, decrypt_aes_ecb
from ciphers.twofish_cipher import generate_twofish_key, encrypt_twofish_ecb, decrypt_twofish_ecb
from ciphers.serpent_cipher import generate_serpent_key, encrypt_serpent_ecb, decrypt_serpent_ecb

# Importowanie do wizualizacji i analizy danych
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd

# Zmienne globalne
current_key = None  # Przechowuje aktualny klucz szyfrowania
wiadomosc_bin = None  # Przechowuje wiadomość w postaci binarnej


# Funkcja zapisująca czas operacji do pliku CSV
def zapisz_czas(operacja, algorytm, czas_ms, dlugosc_we=0, dlugosc_szyf=0):
    # Definicja nagłówków kolumn w pliku CSV
    naglowki = ["Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"]
    # Przygotowanie słownika z danymi do zapisania - każdy klucz odpowiada nagłówkowi
    wiersz = {
        "Operacja": operacja,  # Nazwa operacji: szyfrowanie/deszyfrowanie
        "Algorytm": algorytm,  # Nazwa użytego algorytmu (AES, Twofish, Serpent)
        "Czas (ms)": round(czas_ms, 3),  # Czas operacji w milisekundach, zaokrąglony do 3 miejsc po przecinku
        "Długość wejścia (B)": dlugosc_we,  # Długość oryginalnych danych wejściowych w bajtach
        "Długość szyfrogramu (B)": dlugosc_szyf  # Długość zaszyfrowanych danych (szyfrogramu) w bajtach
    }
    plik = "czasy.csv"  # Nazwa pliku, do którego zapisywane są dane
    nowy = not os.path.exists(plik)  # Sprawdzenie, czy plik istnieje - jeśli nie, trzeba zapisać nagłówki
    try:
        # Otwórz plik w trybie dopisywania ('a'), aby nie nadpisać istniejących danych
        with open(plik, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=naglowki)  # Utwórz writer słownikowy, bazujący na nagłówkach
            if nowy:
                writer.writeheader()  # Jeśli plik nowy, zapisz nagłówki kolumn na początku
            writer.writerow(wiersz)  # Dopisz nowy wiersz z danymi czasu operacji
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się zapisać czasu do pliku:\n{e}")


# Funkcja generująca klucz szyfrujący na podstawie wybranego algorytmu i rozmiaru klucza
def wygeneruj_klucz():
    global current_key
    alg = combo_algorytm.get()  # Pobierz wybrany algorytm z interfejsu (np. AES, Twofish, Serpent)
    bits = int(combo_klucz.get())  # Pobierz rozmiar klucza (np. 128, 192, 256) jako int

    # W zależności od wybranego algorytmu wywołaj odpowiednią funkcję generującą klucz
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
        # Wyświetl wygenerowany klucz w GUI w formie szesnastkowej
        label_klucz.config(text=f"Klucz ({bits} bit): {current_key.hex()}")
    except Exception as e:
        # W przypadku błędu generowania klucza pokaż komunikat błędu
        messagebox.showerror("Błąd", str(e))


# Funkcja szyfrująca wpisaną wiadomość przy użyciu wybranego algorytmu i klucza
def szyfruj():
    global current_key
    alg = combo_algorytm.get()  # Pobierz wybrany algorytm

    # Sprawdź, czy klucz został wygenerowany przed szyfrowaniem
    if not current_key:
        messagebox.showwarning("Brak klucza", "Najpierw wygeneruj klucz!")
        return
    tekst = entry_wiadomosc.get()  # Pobierz tekst do zaszyfrowania z pola tekstowego
    dane_bin = tekst.encode("utf-8")  # Zamień tekst na bajty w UTF-8
    # Jeśli jest podana binarna wersja wiadomości (np. z losowych danych), użyj jej
    if wiadomosc_bin:
        dane_bin = wiadomosc_bin
    # Jeśli pole tekstowe jest puste, wyświetl ostrzeżenie i zakończ
    if not tekst:
        messagebox.showwarning("Brak danych", "Wpisz wiadomość do zaszyfrowania.")
        return
    try:
        start_time = time.perf_counter()  # Zmierz czas rozpoczęcia szyfrowania
        use_padding_flag = use_padding.get()  # Pobierz informację, czy stosować padding

        # W zależności od wybranego algorytmu wywołaj odpowiednią funkcję szyfrującą
        if alg == "AES":
            ciphertext = encrypt_aes_ecb(tekst, current_key, use_padding=use_padding_flag)
        elif alg == "Twofish":
            ciphertext = encrypt_twofish_ecb(tekst, current_key, use_padding=use_padding_flag)
        elif alg == "Serpent":
            ciphertext = encrypt_serpent_ecb(tekst, current_key, use_padding=use_padding_flag)
        else:
            raise ValueError("Nieznany algorytm")
        end_time = time.perf_counter()  # Zmierz czas zakończenia szyfrowania
        czas_szyfrowania = (end_time - start_time) * 1000  # Oblicz czas w milisekundach

        # Aktualizacja GUI - wyświetl długość danych wejściowych i szyfrogramu w bajtach
        label_dlugosc_wiadomosci.config(text=f"Długość wiadomości (binarna): {len(dane_bin)} bajtów")
        label_dlugosc_szyfrowania.config(text=f"Długość szyfrogramu: {len(ciphertext)} bajtów")

        # Zakoduj szyfrogram w base64, by móc go wygodnie wyświetlić i zapisać jako tekst
        wynik_var.set(base64.b64encode(ciphertext).decode())
        # Wyświetl czas szyfrowania w GUI
        label_czas_szyfrowania.config(text=f"Czas szyfrowania: {czas_szyfrowania:.3f} ms")

        # Zapisz czas szyfrowania do pliku CSV razem z informacjami o rozmiarze danych
        zapisz_czas("szyfrowanie", alg, czas_szyfrowania, dlugosc_we=len(dane_bin), dlugosc_szyf=len(ciphertext))
    except Exception as e:
        messagebox.showerror("Błąd", f"Błąd szyfrowania: {e}")


# Funkcja deszyfrująca szyfrogram i wyświetlająca odszyfrowany tekst
def deszyfruj():
    global current_key
    alg = combo_algorytm.get()
    # Sprawdź, czy klucz istnieje przed odszyfrowaniem
    if not current_key:
        messagebox.showwarning("Brak klucza", "Najpierw wygeneruj klucz!")
        return
    try:
        # Pobierz szyfrogram w formacie base64 i zamień go na bajty
        ciphertext = base64.b64decode(wynik_var.get())
        use_padding_flag = use_padding.get()  # Sprawdź, czy używać paddingu
        start_time = time.perf_counter()  # Zmierz czas rozpoczęcia deszyfrowania
        # Deszyfrowanie na podstawie algorytmu
        if alg == "AES":
            plaintext = decrypt_aes_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        elif alg == "Twofish":
            plaintext = decrypt_twofish_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        elif alg == "Serpent":
            plaintext = decrypt_serpent_ecb(ciphertext, current_key, use_padding=use_padding_flag)
        else:
            raise ValueError("Nieznany algorytm")

        end_time = time.perf_counter()  # Zmierz czas zakończenia deszyfrowania
        czas_deszyfrowania = (end_time - start_time) * 1000  # ms
        # Zaktualizuj pole tekstowe wiadomości odszyfrowanej w GUI
        wynik_odszyfrowany_var.set(plaintext)
        # Wyświetl czas deszyfrowania
        label_czas_deszyfrowania.config(text=f"Czas deszyfrowania: {czas_deszyfrowania:.3f} ms")
        # Zapisz czas deszyfrowania do pliku CSV z odpowiednimi parametrami
        zapisz_czas("deszyfrowanie", alg, czas_deszyfrowania, dlugosc_we=len(ciphertext), dlugosc_szyf=len(plaintext))
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się odszyfrować:\n{e}")


# Funkcja do wyświetlania tabeli z zapisanymi czasami operacji (szyfrowania/deszyfrowania)
def pokaz_tabele():
    csv_file = "czasy.csv" # Plik CSV z zapisanymi danymi
    # Sprawdź, czy plik istnieje, jeśli nie - wyświetl komunikat i zakoncz
    if not os.path.exists(csv_file):
        messagebox.showinfo("Brak danych", "Plik z czasami nie istnieje.")
        return
    # Tworzymy nowe okno typu Toplevel (nowe okno niezależne od głównego)
    tabela_okno = tk.Toplevel(root)
    tabela_okno.title("Tabela czasów operacji") # Ustaw tytuł okna
    tabela_okno.geometry("900x300") # Rozmiar okna

    # Tworzymy widget Treeview (tabela) z 5 kolumnami i bez kolumny z numerem wiersza
    tree = ttk.Treeview(tabela_okno,
                        columns=("Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"),
                        show="headings") # show="headings" - tylko nagłówki, bez domyślnej kolumny

    # Konfiguracja nagłówków i szerokości kolumn tabeli
    for col in ("Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"):
        tree.heading(col, text=col) # Ustaw tekst nagłówka kolumny
        tree.column(col, width=100) # Ustaw szerokość kolumny na 100 pikseli
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) # Umieść tabelę i pozwól jej rozciągać się

    # Wczytanie danych z pliku CSV i wstawienie ich do tabeli
    try:
        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) # Pomijamy pierwszy wiersz - nagłówek CSV
            for row in reader:
                if len(row) == 5:
                    tree.insert("", tk.END, values=row) # Dodaj wiersz do tabeli
    except Exception as e:
        # Jeśli jest problem z plikiem CSV, pokaż błąd
        messagebox.showerror("Błąd", f"Błąd wczytywania CSV:\n{e}")

    # Funkcja usuwająca wybrany zaznaczony wiersz z tabeli i pliku CSV
    def usun_wybrany():
        zaznaczone = tree.selection() # Pobierz zaznaczone wiersze
        if not zaznaczone:
            messagebox.showinfo("Brak wyboru", "Wybierz wiersz do usunięcia.")
            return

        for item in zaznaczone:
            wartosci = tree.item(item)["values"] # Pobierz wartości z zaznaczonego wiersza
            tree.delete(item) # Usuń wiersz z tabeli

            # Usuń także ten wiersz z pliku CSV
            with open(csv_file, newline='', encoding='utf-8') as f:
                rows = list(csv.reader(f))
            with open(csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(rows[0])  # Zapisz nagłówek
                for r in rows[1:]:
                    # Przepisz wszystkie wiersze poza tym, który chcemy usunąć
                    if r != list(map(str, wartosci)):
                        writer.writerow(r)

    # Funkcja usuwająca wszystkie dane z tabeli i pliku CSV (po potwierdzeniu)
    def usun_wszystkie():
        if messagebox.askyesno("Potwierdzenie", "Czy na pewno chcesz usunąć wszystkie dane?"):
            # Usuń wszystkie wiersze z tabeli
            for item in tree.get_children():
                tree.delete(item)
                # Zapisz do pliku CSV tylko nagłówek
            with open(csv_file, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Operacja", "Algorytm", "Czas (ms)", "Długość wejścia (B)", "Długość szyfrogramu (B)"])

    # Funkcja eksportująca aktualne dane z tabeli do nowego pliku CSV wybranego przez użytkownika
    def eksportuj_csv():
        nowa_sciezka = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if nowa_sciezka:
            try:
                with open(nowa_sciezka, "w", newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Nagłówek w pliku eksportowanym - tu masz inny układ, możesz ujednolicić jeśli chcesz
                    writer.writerow(["Operacja", "Algorytm", "Rozmiar", "Padding", "Czas (ms)"])
                    for row_id in tree.get_children():
                        writer.writerow(tree.item(row_id)["values"]) # Zapisz każdą linię z tabeli
                messagebox.showinfo("Eksport zakończony", f"Dane zapisane do {nowa_sciezka}")
            except Exception as e:
                messagebox.showerror("Błąd eksportu", str(e))

    # Ramka na przyciski pod tabelą
    przyciski_frame = tk.Frame(tabela_okno)
    przyciski_frame.pack(pady=5)

    # Przyciski: usuwanie zaznaczonego, usuwanie wszystkich, eksport
    tk.Button(przyciski_frame, text="Usuń wybrany wiersz", command=usun_wybrany).grid(row=0, column=0, padx=5)
    tk.Button(przyciski_frame, text="Usuń wszystkie dane", command=usun_wszystkie).grid(row=0, column=1, padx=5)
    tk.Button(przyciski_frame, text="Eksportuj do CSV", command=eksportuj_csv).grid(row=0, column=2, padx=5)


def losowa_dlugosc():
    global wiadomosc_bin
    # Pobieramy aktualny wybór długości danych z widgetu combo_dane (Combobox)
    wybor = combo_dane.get()
    # Słownik mapujący etykiety długości na liczbę bajtów
    rozmiary = {
        "16B": 16,
        "32B": 32,
        "64B": 64,
        "128B": 128,
        "1KB": 1024,
        "10KB": 10240,
    }
    # Pobieramy liczbę bajtów odpowiadającą wybranemu rozmiarowi
    liczba = rozmiary.get(wybor)
    # Jeśli wybrana długość nie jest poprawna (np. puste lub nieznane), pokazujemy błąd
    if liczba is None:
        messagebox.showerror("Błąd", "Wybierz prawidłową długość danych.")
        return

    # Definiujemy zestaw znaków ASCII do generowania losowego tekstu:
    # małe i wielkie litery, cyfry oraz znaki specjalne
    znaki = string.ascii_letters + string.digits + string.punctuation
    # Generujemy losowy ciąg znaków o długości 'liczba'
    losowy_tekst = ''.join(random.choices(znaki, k=liczba))

    # Ustawiamy wygenerowany tekst w zmiennej powiązanej z widgetem
    wynik_losowy.set(losowy_tekst)
    # Konwertujemy tekst na bajty UTF-8, zapisujemy globalnie do 'wiadomosc_bin'
    wiadomosc_bin = losowy_tekst.encode("utf-8")


def pokaz_wykresy():
    # Sprawdzamy, czy plik z danymi "czasy.csv" istnieje, jeśli nie, wyświetlamy info i wychodzimy
    if not os.path.exists("czasy.csv"):
        messagebox.showinfo("Brak danych", "Brak pliku z danymi.")
        return
    # Wczytujemy dane z pliku CSV do DataFrame Pandas
    df = pd.read_csv("czasy.csv")
    # Jeśli DataFrame jest pusty, informujemy użytkownika i wychodzimy
    if df.empty:
        messagebox.showinfo("Brak danych", "Plik CSV jest pusty.")
        return

    # Funkcja do rysowania wykresów w zależności od wybranej opcji
    def rysuj_wykres(wybor):
        plt.clf() # Czyścimy poprzedni wykres (jeśli jest)
        fig, ax = plt.subplots(figsize=(8, 5))  # Tworzymy nową figurę i oś wykresu o określonym rozmiarze
        # Warunki dopasowujące wykres do wybranej opcji
        if wybor == "Czas vs Algorytm":
            df.groupby("Algorytm")["Czas (ms)"].mean().plot(kind="bar", ax=ax)
            ax.set_ylabel("Średni czas (ms)")
        elif wybor == "Czas vs Długość wejścia":
            df.groupby("Długość wejścia (B)")["Czas (ms)"].mean().plot(ax=ax)
            ax.set_ylabel("Średni czas (ms)")
        elif wybor == "Czas szyfrowania vs deszyfrowania":
            df.groupby(["Operacja"])["Czas (ms)"].mean().plot(kind="bar", ax=ax)
            ax.set_ylabel("Średni czas (ms)")
        elif wybor == "Czas (ms) w zależności od algorytmu i długości":
            df.groupby(["Algorytm", "Długość wejścia (B)"])["Czas (ms)"].mean().unstack().T.plot(ax=ax)
            ax.set_ylabel("Średni czas (ms)")
        elif wybor == "Rozrzut czasów wg algorytmu":
            df.boxplot(column="Czas (ms)", by="Algorytm", ax=ax)
            plt.suptitle("")
            ax.set_title("Rozrzut czasów wg algorytmu")
        elif wybor == "Czas vs Długość szyfrogramu":
            df.groupby("Długość szyfrogramu (B)")["Czas (ms)"].mean().plot(ax=ax)
            ax.set_ylabel("Średni czas (ms)")
        # Ustawiamy etykiety osi X i tytuł wykresu
        ax.set_xlabel(wybor)
        ax.set_title(wybor)
        ax.grid(True) # Siatka na wykresie
        plt.tight_layout() # Dobre rozmieszczenie elementów wykresu
        return fig # Zwracamy obiekt figury Matplotlib

    # Funkcja wywoływana przy zmianie wyboru w comboboxie wykresów
    def pokaz_wybrany_wykres(event):
        wybor = combo_wykres.get()  # Pobieramy wybraną opcję
        fig = rysuj_wykres(wybor) # Rysujemy wykres dla tej opcji
        # Usuwamy poprzedni widget wykresu, jeśli istnieje
        for widget in plot_frame.winfo_children():
            widget.destroy()
        # Tworzymy i wstawiamy nowy widget canvas z wykresem Matplotlib
        canvas = FigureCanvasTkAgg(fig, master=plot_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    # Tworzymy nowe okno Toplevel dla wykresów
    wykres_okno = tk.Toplevel(root)
    wykres_okno.title("Wykresy porównawcze")
    wykres_okno.geometry("900x600")
    # Lista opcji wykresów dostępnych do wyboru w Combobox
    opcje = [
        "Czas vs Algorytm",
        "Czas vs Długość wejścia",
        "Czas szyfrowania vs deszyfrowania",
        "Czas (ms) w zależności od algorytmu i długości",
        "Rozrzut czasów wg algorytmu",
        "Czas vs Długość szyfrogramu"
    ]
    # Tworzymy Combobox do wyboru wykresu, ustawiamy na readonly i wybieramy pierwszą opcję domyślnie
    combo_wykres = ttk.Combobox(wykres_okno, values=opcje, state="readonly")
    combo_wykres.current(0)
    combo_wykres.pack(pady=5)
    combo_wykres.bind("<<ComboboxSelected>>", pokaz_wybrany_wykres)

    # Ramka do wyświetlania wykresu w oknie
    plot_frame = tk.Frame(wykres_okno)
    plot_frame.pack(fill=tk.BOTH, expand=True)
    
    # Na start pokazujemy domyślny pierwszy wykres (przekazujemy None bo nie ma eventu)
    pokaz_wybrany_wykres(None)  # domyślnie pierwszy wykres


# --- GUI ---
root = tk.Tk()
root.title("Szyfrowanie blokowe – AES / Twofish / Serpent")
root.geometry("600x600")
frame_wiadomosc = tk.Frame(root)
frame_wiadomosc.pack(pady=5)
tk.Label(frame_wiadomosc, text="Wiadomość:").pack()
wynik_losowy = tk.StringVar()
entry_wiadomosc = tk.Entry(frame_wiadomosc, textvariable=wynik_losowy, width=60)
entry_wiadomosc.pack(side=tk.LEFT, padx=5)
btn_czysc = tk.Button(frame_wiadomosc, text="Wyczyść", command=lambda: entry_wiadomosc.delete(0, tk.END))
btn_czysc.pack(side=tk.LEFT)
frame_losowa = tk.Frame(root)
frame_losowa.pack(pady=5)
tk.Label(frame_losowa, text="Losowa treść:").pack()
combo_dane = ttk.Combobox(frame_losowa, values=["16B", "32B", "64B", "128B", "1KB", "10KB"], state="readonly")
combo_dane.current(0)
combo_dane.pack(side=tk.LEFT)
tk.Button(frame_losowa, text="Generuj", command=losowa_dlugosc).pack(side=tk.LEFT, padx=5)

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
tk.Button(root, text="Pokaż wykresy", command=pokaz_wykresy).pack(pady=5)
root.mainloop()
