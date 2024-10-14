## Kryptografia i Teoria Kodów - Projekt

#### Utworzenie środowiska:
    python -m venv venv

#### Aktywacja środowiska:
	venv\Scripts\activate

#### Stworzenie pliku requirements.txt:
	pip freeze > requirements.txt

#### Instalacja pakietów z requirements.txt:
	pip install -r requirements.txt

#### Uruchomienie projektu
    python main.py

#### Zamknięcie wirtualnego środowiska:
	deactivate

#### Konwertowanie pliku .ui na kod Pythona:
	pyuic5 -x MainWindow.ui -o MainWindow.py
