def szyfruj(tekst, klucz):
    """
    Szyfruje podany tekst za pomocą podstawienia opierającego się na unikalnym kluczu.

    Args:
        tekst (str): Tekst do zaszyfrowania.
        klucz (str): Unikalny klucz szyfrujący, zawierający litery alfabetu.

    Returns:
        str: Zaszyfrowany tekst.
    """
    # Definicja podstawowego alfabetu
    alfabet = "abcdefghijklmnopqrstuvwxyz"

    # Usunięcie duplikatów z klucza i zachowanie oryginalnej kolejności liter
    klucz = "".join(sorted(set(klucz), key=klucz.index))

    # Dodanie do klucza pozostałych liter alfabetu, które nie znajdują się w kluczu
    pozostale_litery = [char for char in alfabet if char not in klucz]
    alfabet_szyfrowy = klucz + "".join(pozostale_litery)

    # Proces szyfrowania tekstu
    szyfr = ""
    for char in tekst:
        if char in alfabet:
            # Znalezienie odpowiedniego indeksu w alfabecie
            index = alfabet.index(char)
            # Zastąpienie litery z podstawowego alfabetu odpowiednią literą z alfabetu szyfrowego
            szyfr += alfabet_szyfrowy[index]
        else:
            # Dodanie znaków, które nie są w alfabecie, bez zmian
            szyfr += char

    return szyfr


def odszyfruj(tekst, klucz):
    """
    Odszyfrowuje podany tekst zaszyfrowany za pomocą szyfru podstawieniowego.

    Args:
        tekst (str): Tekst do odszyfrowania.
        klucz (str): Klucz użyty do zaszyfrowania tekstu.

    Returns:
        str: Odszyfrowany tekst.
    """
    # Definicja podstawowego alfabetu
    alfabet = "abcdefghijklmnopqrstuvwxyz"

    # Usunięcie duplikatów z klucza i zachowanie oryginalnej kolejności liter
    klucz = "".join(sorted(set(klucz), key=klucz.index))

    # Dodanie do klucza pozostałych liter alfabetu, które nie znajdują się w kluczu
    pozostale_litery = [char for char in alfabet if char not in klucz]
    alfabet_szyfrowy = klucz + "".join(pozostale_litery)

    # Proces odszyfrowania tekstu
    odszyfrowany = ""
    for char in tekst:
        if char in alfabet_szyfrowy:
            # Znalezienie odpowiedniego indeksu w alfabecie szyfrowym
            index = alfabet_szyfrowy.index(char)
            # Zastąpienie litery z alfabetu szyfrowego odpowiednią literą z podstawowego alfabetu
            odszyfrowany += alfabet[index]
        else:
            # Dodanie znaków, które nie są w alfabecie szyfrowym, bez zmian
            odszyfrowany += char

    return odszyfrowany
