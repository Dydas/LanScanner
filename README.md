# LAN Scanner

Desktopowa aplikacja (Python + Tkinter), która skanuje adresy IP w sieci lokalnej
i wyświetla ich hostname (DNS → NetBIOS), adres MAC i czas pingu.

## Pobieranie

Gotowe pliki są w zakładce **Releases**:

- `LanScanner.exe` — Windows 10/11
- `LanScanner-macOS-arm64.dmg` — macOS 12+ na Apple Silicon

### macOS — pierwsze uruchomienie

Aplikacja nie jest podpisana certyfikatem Apple Developer:

1. Przeciągnij `LanScanner.app` do Aplikacji.
2. Uruchom; przy blokadzie: Ustawienia systemowe → Prywatność i ochrona → „Otwórz mimo to”
   (lub `xattr -dr com.apple.quarantine /Applications/LanScanner.app`).
3. Zezwól na dostęp do **sieci lokalnej**, gdy system zapyta — bez tego skan nic nie znajdzie.

## Budowanie

- Windows: `pyinstaller --onefile --windowed --name LanScanner lan_scanner.py`
- macOS: `./build_macos.sh`
- CI: push tagu `v*` buduje obie wersje i publikuje Release.
