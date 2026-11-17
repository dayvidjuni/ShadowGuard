@echo off
title ShadowGuard - Escudo de Seguridad DLP
cls
echo ========================================================
echo       Iniciando ShadowGuard (Escudo Anti-Fuga de IA)
echo ========================================================
echo.
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no fue detectado en el sistema.
    echo Por favor instala Python 3.9 o superior desde https://www.python.org/
    pause
    exit /b
)

python main.py
pause
