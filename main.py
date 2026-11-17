"""main.py - Lanzador unificado y amigable de ShadowGuard.

Inicia simultáneamente el monitor en segundo plano y el dashboard web,
abriendo automáticamente la interfaz para el usuario.
"""
import argparse
import os
import sys
import threading
import time
import webbrowser

import uvicorn

import config
import database
from monitor import MonitorDemonio


def main():
    parser = argparse.ArgumentParser(
        description="ShadowGuard - Sistema de Protección Local contra Fuga de Secretos en IA"
    )
    parser.add_argument(
        "--modo",
        choices=["sanitizar", "alerta", "pausado"],
        default=None,
        help="Modo de operación inicial (sanitizar / alerta / pausado)",
    )
    parser.add_argument(
        "--solo-monitor",
        action="store_true",
        help="Ejecuta únicamente el monitor de portapapeles sin servidor web",
    )
    parser.add_argument(
        "--solo-web",
        action="store_true",
        help="Ejecuta únicamente el panel web sin el monitor de portapapeles",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="No abrir el navegador automáticamente",
    )
    parser.add_argument(
        "--puerto",
        type=int,
        default=None,
        help="Puerto para el panel web (por defecto: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host para el panel web (por defecto: 127.0.0.1)",
    )
    args = parser.parse_args()

    cfg = config.cargar_config()
    if args.modo:
        cfg["modo"] = args.modo
    if args.puerto:
        cfg["puerto_dashboard"] = args.puerto
    if args.host:
        cfg["host_dashboard"] = args.host
    config.guardar_config(cfg)

    host = cfg.get("host_dashboard", "127.0.0.1")
    puerto = cfg.get("puerto_dashboard", 8000)
    modo = cfg.get("modo", "sanitizar")

    print("\n" + "=" * 65)
    print("   🛡️   SHADOWGUARD 2.0 - ESCUDO DLP ANTI-FUGA DE SECRETOS")
    print("=" * 65)
    print(f" • Estado del Escudo:    ACTIVO (Modo: {modo.upper()})")
    print(f" • Estrategia Máscara:   {cfg.get('estrategia_mascara', 'asteriscos')}")
    print(f" • Notificaciones:       {'Activadas' if cfg.get('notificaciones_activadas', True) else 'Desactivadas'}")
    print(f" • Panel de Control Web: http://{host}:{puerto}")
    print("=" * 65)
    print(" Protegiendo contra pegado accidental en ChatGPT, Claude, Gemini...")
    print(" Presiona Ctrl+C en cualquier momento para salir.\n")

    demonio = None
    if not args.solo_web:
        demonio = MonitorDemonio()
        demonio.iniciar(bloqueante=False)
        print("[+] Monitor de portapapeles iniciado en segundo plano.")

    if not args.solo_monitor:
        if not args.no_browser:
            def _abrir_web():
                time.sleep(1.2)
                webbrowser.open(f"http://{host}:{puerto}")
            threading.Thread(target=_abrir_web, daemon=True).start()

        try:
            uvicorn.run("dashboard.main:app", host=host, port=puerto, log_level="warning")
        except KeyboardInterrupt:
            pass
        finally:
            if demonio:
                demonio.detener()
            print("\n[ShadowGuard] Sistema detenido limpiamente.")
    else:
        # Solo monitor bloqueante
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            if demonio:
                demonio.detener()
            print("\n[ShadowGuard] Monitor detenido.")


if __name__ == "__main__":
    main()
