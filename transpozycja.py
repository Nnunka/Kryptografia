def szyfruj(tekst, klucz):
    tekst = tekst.replace(" ", "#")
    dlugosc = len(tekst)
    dodatek = klucz - (dlugosc % klucz)
    tekst += "#" * dodatek if dodatek != klucz else ""

    macierz = [tekst[i:i+klucz] for i in range(0, len(tekst), klucz)]
    szyfr = ""
    for i in range(klucz):
        for wiersz in macierz:
            szyfr += wiersz[i]
    return szyfr

def odszyfruj(tekst, klucz):
    dlugosc = len(tekst)
    wiersze = dlugosc // klucz
    macierz = [''] * wiersze

    index = 0
    for i in range(klucz):
        for j in range(wiersze):
            macierz[j] += tekst[index]
            index += 1

    return ''.join(macierz).replace("#", " ")
