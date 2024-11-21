import secrets
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from sympy import isprime


class DiffieHellman:
    """
    Klasa implementująca protokół wymiany klucza Diffiego-Hellmana, 
    z dodatkową obsługą szyfrowania i deszyfrowania wiadomości za pomocą AES.

    Protokół pozwala na bezpieczne ustalenie wspólnego klucza pomiędzy dwiema stronami.
    """

    def __init__(self, p, g):
        """
        Inicjalizuje obiekt DiffieHellman z podanymi wartościami p (liczba pierwsza) i g (podstawa).

        Args:
            p (int): Liczba pierwsza większa niż 2.
            g (int): Podstawa (1 < g < p).
        
        Raises:
            ValueError: Jeśli p nie jest liczbą pierwszą, jest zbyt małe lub g nie spełnia warunków.
        """
        if not isprime(p):
            raise ValueError("p musi być liczbą pierwszą.")
        if not (1 < g < p):
            raise ValueError("g musi być większe niż 1 i mniejsze niż p.")
        if p <= 2:
            raise ValueError("p musi być liczbą pierwszą większą niż 2.")
        
        self.p = p
        self.g = g
        self.private_key = secrets.randbelow(self.p - 2) + 1  # Klucz prywatny: 1 <= private_key < p - 1
        self.public_key = pow(self.g, self.private_key, self.p)  # Klucz publiczny

    def compute_shared_secret(self, other_public_key):
        """
        Oblicza wspólny sekret na podstawie klucza publicznego drugiej strony.

        Args:
            other_public_key (int): Klucz publiczny drugiej strony.
        
        Returns:
            int: Wspólny sekret obliczony przy użyciu klucza prywatnego i klucza publicznego drugiej strony.
        
        Raises:
            ValueError: Jeśli klucz publiczny drugiej strony jest nieprawidłowy.
        """
        if not (1 <= other_public_key < self.p):
            raise ValueError("Klucz publiczny drugiej strony jest niepoprawny.")
        return pow(other_public_key, self.private_key, self.p)

    @staticmethod
    def derive_key(shared_secret):
        """
        Wyprowadza klucz AES z obliczonego wspólnego sekretu przy użyciu funkcji skrótu SHA-256.

        Args:
            shared_secret (int): Wspólny sekret obliczony przy użyciu Diffie-Hellmana.

        Returns:
            bytes: Klucz AES (32 bajty).
        """
        return sha256(str(shared_secret).encode()).digest()

    @staticmethod
    def encrypt_message(message, key):
        """
        Szyfruje wiadomość za pomocą algorytmu AES w trybie CBC.

        Args:
            message (str): Wiadomość do zaszyfrowania.
            key (bytes): Klucz AES (32 bajty).
        
        Returns:
            str: Zaszyfrowana wiadomość zakodowana w Base64.
        
        Raises:
            ValueError: Jeśli wiadomość nie jest tekstem lub klucz AES ma nieprawidłową długość.
        """
        if not isinstance(message, str):
            raise ValueError("Wiadomość musi być ciągiem tekstowym.")
        if len(key) != 32:  # Klucz AES musi być 256-bitowy
            raise ValueError("Klucz AES musi mieć długość 32 bajty.")
        
        # Tworzenie obiektu szyfrującego w trybie CBC
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv  # Wektor inicjalizujący (IV)

        # Szyfrowanie wiadomości z dodaniem wypełnienia
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

        # Zakodowanie IV i zaszyfrowanych danych w Base64
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def decrypt_message(encrypted_message, key):
        """
        Odszyfrowuje wiadomość zaszyfrowaną za pomocą algorytmu AES w trybie CBC.

        Args:
            encrypted_message (str): Zaszyfrowana wiadomość zakodowana w Base64.
            key (bytes): Klucz AES (32 bajty).
        
        Returns:
            str: Odszyfrowana wiadomość.
        
        Raises:
            ValueError: Jeśli klucz AES ma nieprawidłową długość.
        """
        if len(key) != 32:  # Klucz AES musi być 256-bitowy
            raise ValueError("Klucz AES musi mieć długość 32 bajty.")
        
        # Dekodowanie danych Base64
        data = base64.b64decode(encrypted_message)

        # Wyodrębnienie wektora inicjalizującego (IV) i zaszyfrowanych danych
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]

        # Tworzenie obiektu deszyfrującego w trybie CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Deszyfrowanie wiadomości i usunięcie wypełnienia
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
