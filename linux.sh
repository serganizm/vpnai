#!/bin/sh
cd "$(dirname "$0")/app" || exit 1
if [ -x .venv/bin/python ]; then exec .venv/bin/python app.py; fi
if command -v python3 >/dev/null 2>&1; then exec python3 app.py; fi
echo 'Установите Python 3.9 или новее с python.org и запустите linux.sh снова.'
read -r answer
