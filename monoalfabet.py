def szyfruj(tekst, slowo_klucz):
    alfabet = "abcdefghijklmnopqrstuvwxyz"
    slowo_klucz = "".join(sorted(set(slowo_klucz), key=slowo_klucz.index))
    pozostale_litery = [char for char in alfabet if char not in slowo_klucz]
    alfabet_szyfrowy = slowo_klucz + "".join(pozostale_litery)

    szyfr = ""
    for char in tekst:
        if char in alfabet:
            index = alfabet.index(char)
            szyfr += alfabet_szyfrowy[index]
        else:
            szyfr += char
    return szyfr

def odszyfruj(tekst, slowo_klucz):
    alfabet = "abcdefghijklmnopqrstuvwxyz"
    slowo_klucz = "".join(sorted(set(slowo_klucz), key=slowo_klucz.index))
    pozostale_litery = [char for char in alfabet if char not in slowo_klucz]
    alfabet_szyfrowy = slowo_klucz + "".join(pozostale_litery)

    odszyfrowany = ""
    for char in tekst:
        if char in alfabet_szyfrowy:
            index = alfabet_szyfrowy.index(char)
            odszyfrowany += alfabet[index]
        else:
            odszyfrowany += char
    return odszyfrowany
