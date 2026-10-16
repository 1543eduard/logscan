#!/bin/bash
# Instalare logscan pe o masina noua (Linux / macOS), din folderul clonat:
#   ./install.sh            -> creeaza venv/ si instaleaza dependintele
#   ./install.sh --link     -> in plus, comanda "logscan" in /usr/local/bin
#                              (cere drepturi de scriere acolo, de ex. root / sudo)
# Actualizare ulterioara: git pull (comanda "logscan" foloseste direct repo-ul).
set -e
APP_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$APP_DIR"
# numpy 2.x cere Python >= 3.11; pe multe servere "python3" e mai vechi
# (AlmaLinux / CentOS 8: 3.6), deci cautam cel mai nou interpretor disponibil.
ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; }
PY=""
for c in ${PYTHON:-} python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && ok "$c"; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "Lipseste Python 3.11 sau mai nou (python3 de aici: $(python3 --version 2>&1))."
    echo "Instaleaza-l, de ex.:  dnf install python3.11   |   apt install python3.11 python3.11-venv   |   brew install python@3.12"
    exit 1
fi
if [ -x venv/bin/python ] && ! ok venv/bin/python; then
    echo "-> venv/ e facut cu un Python prea vechi ($(venv/bin/python --version 2>&1)); il refac"
    rm -rf venv
fi
if [ ! -x venv/bin/python ]; then
    echo "-> creez venv/ cu $PY ($("$PY" --version 2>&1))"
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
