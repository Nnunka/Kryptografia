def szyfruj(tekst, klucz):
    """
    Szyfruje tekst za pomocą szyfru macierzowego z podanym kluczem.

    Proces polega na uzupełnieniu tekstu do wielokrotności klucza, 
    podziale na wiersze o długości klucza i odczytywaniu kolumn.

    Args:
        tekst (str): Tekst do zaszyfrowania.
        klucz (int): Liczba określająca liczbę kolumn macierzy szyfrującej.

    Returns:
        str: Zaszyfrowany tekst.
    """
    # Zamiana spacji na znak specjalny (np. #), aby móc później je odtworzyć
    tekst = tekst.replace(" ", "#")

    # Obliczenie długości tekstu
    dlugosc = len(tekst)

    # Obliczenie liczby znaków, które należy dodać, aby długość była wielokrotnością klucza
    dodatek = klucz - (dlugosc % klucz)
    # Dodanie znaków uzupełniających tylko, jeśli nie jest już wielokrotnością klucza
    tekst += "#" * dodatek if dodatek != klucz else ""

    # Podział tekstu na wiersze o długości klucza
    macierz = [tekst[i:i+klucz] for i in range(0, len(tekst), klucz)]

    # Odczytywanie znaków kolumnami
    szyfr = ""
    for i in range(klucz):  # Iteracja przez kolumny
        for wiersz in macierz:  # Iteracja przez wiersze
            szyfr += wiersz[i]

    return szyfr


def odszyfruj(tekst, klucz):
    """
    Odszyfrowuje tekst zaszyfrowany za pomocą szyfru macierzowego.

    Proces polega na rekonstrukcji wierszy macierzy z kolumn tekstu szyfrowanego 
    i późniejszej zamianie znaków specjalnych na spacje.

    Args:
        tekst (str): Zaszyfrowany tekst do odszyfrowania.
        klucz (int): Liczba określająca liczbę kolumn macierzy szyfrującej.

    Returns:
        str: Odszyfrowany tekst.
    """
    # Obliczenie liczby wierszy w macierzy na podstawie długości tekstu
    dlugosc = len(tekst)
    wiersze = dlugosc // klucz

    # Przygotowanie pustej macierzy na wiersze
    macierz = [''] * wiersze

    # Odczytywanie tekstu kolumnami i zapisanie go w odpowiednich wierszach
    index = 0
    for i in range(klucz):  # Iteracja przez kolumny
        for j in range(wiersze):  # Iteracja przez wiersze
            macierz[j] += tekst[index]
            index += 1

    # Połączenie wierszy w pełny tekst i zamiana znaku specjalnego (#) na spację
    return ''.join(macierz).replace("#", " ")
