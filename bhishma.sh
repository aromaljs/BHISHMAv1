#!/bin/bash

cd "$(dirname "$0")" || exit

if [ ! -d "env" ]; then
echo "[*] Creating virtual environment..."
python3 -m venv env
fi

source env/bin/activate

echo "[*] Installing requirements..."
pip install -r requirements.txt >/dev/null 2>&1

echo "[*] Launching BHISHMA..."
python3 main.py
