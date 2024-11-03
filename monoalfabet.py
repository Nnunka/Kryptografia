def szyfruj(tekst, klucz):
    alfabet = "abcdefghijklmnopqrstuvwxyz"
    klucz = "".join(sorted(set(klucz), key=klucz.index))
    pozostale_litery = [char for char in alfabet if char not in klucz]
    alfabet_szyfrowy = klucz + "".join(pozostale_litery)

    szyfr = ""
    for char in tekst:
        if char in alfabet:
            index = alfabet.index(char)
            szyfr += alfabet_szyfrowy[index]
        else:
            szyfr += char
    return szyfr

def odszyfruj(tekst, klucz):
    alfabet = "abcdefghijklmnopqrstuvwxyz"
    klucz = "".join(sorted(set(klucz), key=klucz.index))
    pozostale_litery = [char for char in alfabet if char not in klucz]
    alfabet_szyfrowy = klucz + "".join(pozostale_litery)

    odszyfrowany = ""
    for char in tekst:
        if char in alfabet_szyfrowy:
            index = alfabet_szyfrowy.index(char)
            odszyfrowany += alfabet[index]
        else:
            odszyfrowany += char
    return odszyfrowany
