import os
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.hashes import SHA256

def ensure_data_folder():
    """
    Tworzy folder 'data', jeśli jeszcze nie istnieje.
    """
    if not os.path.exists("data"):
        os.makedirs("data")

def generate_hmac_key():
    """
    Generuje klucz HMAC i zapisuje go w folderze 'data'.
    """
    ensure_data_folder()

    # Generowanie losowego klucza HMAC
    key = os.urandom(32)  # Klucz 256-bitowy

    # Zapisanie klucza
    key_path = os.path.join("data", "hmac_key.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    return key_path

def load_hmac_key():
    """
    Ładuje klucz HMAC z pliku.
    """
    key_path = os.path.join("data", "hmac_key.key")
    if not os.path.exists(key_path):
        raise FileNotFoundError("Klucz HMAC nie został wygenerowany.")
    with open(key_path, "rb") as key_file:
        return key_file.read()

def calculate_hmac(file_path, key):
    """
    Oblicza HMAC dla pliku PDF.

    Args:
        file_path (str): Ścieżka do pliku PDF.
        key (bytes): Klucz HMAC.

    Returns:
        bytes: Wygenerowany HMAC.
    """
    # Wczytaj zawartość pliku
    with open(file_path, "rb") as f:
        data = f.read()

    # Oblicz HMAC
    h = hmac.HMAC(key, SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(file_path, provided_hmac, key):
    """
    Weryfikuje HMAC pliku PDF.

    Args:
        file_path (str): Ścieżka do pliku PDF.
        provided_hmac (bytes): Oczekiwany HMAC.
        key (bytes): Klucz HMAC.

    Returns:
        bool: True, jeśli HMAC jest poprawny, False w przeciwnym razie.
    """
    # Wczytaj zawartość pliku
    with open(file_path, "rb") as f:
        data = f.read()

    # Weryfikacja HMAC
    h = hmac.HMAC(key, SHA256())
    h.update(data)
    try:
        h.verify(provided_hmac)
        return True
    except Exception:
        return False
