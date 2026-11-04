#!/bin/bash
# Buduje LanScanner.app + LanScanner-macOS-arm64.dmg na Macu z Apple Silicon.
# Wymaga Pythona z python.org (zawiera Tk) lub: brew install python python-tk
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
"$PY" -c "import tkinter; print('Tk', tkinter.TkVersion)"

"$PY" -m venv .venv-mac
source .venv-mac/bin/activate
pip install --quiet --upgrade pip pyinstaller

pyinstaller --noconfirm --clean LanScanner-macos.spec

rm -f dist/LanScanner-macOS-arm64.dmg
hdiutil create -volname "LAN Scanner" -srcfolder dist/LanScanner.app \
  -ov -format UDZO dist/LanScanner-macOS-arm64.dmg

echo "Gotowe: dist/LanScanner.app oraz dist/LanScanner-macOS-arm64.dmg"
