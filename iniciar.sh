#!/usr/bin/env bash
echo "========================================================"
echo "      Iniciando ShadowGuard (Escudo Anti-Fuga de IA)    "
echo "========================================================"
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 no está instalado."
    exit 1
fi
python3 main.py
