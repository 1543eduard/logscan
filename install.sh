#!/bin/bash
# Instalare logscan pe o masina noua (Linux / macOS), din folderul clonat:
#   ./install.sh            -> creeaza venv/ si instaleaza dependintele
#   ./install.sh --link     -> in plus, comanda "logscan" in /usr/local/bin
#                              (cere drepturi de scriere acolo, de ex. root / sudo)
# Actualizare ulterioara: git pull (comanda "logscan" foloseste direct repo-ul).
set -e
APP_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$APP_DIR"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || { echo "Lipseste $PY (Python 3; testat pe 3.11)."; exit 1; }
if [ ! -x venv/bin/python ]; then
    echo "-> creez venv/"
    "$PY" -m venv venv
fi
echo "-> instalez dependintele (requirements.txt)"
venv/bin/python -m pip install -q --upgrade pip
venv/bin/python -m pip install -q -r requirements.txt
chmod +x bin/logscan
if [ "$1" = "--link" ]; then
    ln -sf "$APP_DIR/bin/logscan" /usr/local/bin/logscan
    echo "-> comanda 'logscan' -> $APP_DIR/bin/logscan"
fi
echo "Gata. Porneste cu:  $APP_DIR/bin/logscan   (sau 'logscan' daca ai folosit --link)"
