"""monitor.py - Demonio de vigilancia del portapapeles con detección, sanitización y alertas.

Uso:
    python monitor.py [--modo sanitizar|alerta|pausado] [--intervalo 0.5]
"""
import argparse
import hashlib
import sys
import threading
import time
from typing import List, Tuple

import clipboard
from config import cargar_config, guardar_config
import database
from detector import Hallazgo, detectar
from notifier import notificar
from sanitizer import sanitizar


def calcular_hash(texto: str) -> str:
    return hashlib.md5(texto.encode("utf-8", errors="ignore")).hexdigest()


def procesar(
    texto: str,
    modo: str = "sanitizar",
    db: str = database.DB_POR_DEFECTO,
    origen: str = "portapapeles",
    estrategia: str = "asteriscos",
) -> Tuple[str, List[Hallazgo]]:
    """Analiza el texto, detecta secretos, registra el incidente y sanitiza si corresponde."""
    if not texto or modo == "pausado":
        return texto, []

    hallazgos = detectar(texto)
    if not hallazgos:
        return texto, []

    accion = "sanitizado" if modo == "sanitizar" else "alerta"

    # Registrar en base de datos sin almacenar el secreto
    for h in hallazgos:
        database.registrar(
            tipo=h.tipo,
            metodo=h.metodo,
            longitud=h.fin - h.inicio,
            accion=accion,
            origen=origen,
            severidad=h.severidad,
            ruta=db,
        )

    texto_final = sanitizar(texto, hallazgos, estrategia) if modo == "sanitizar" else texto
    return texto_final, hallazgos


class MonitorDemonio:
    """Demonio de monitoreo continuo del portapapeles."""

    def __init__(self, db: str = database.DB_POR_DEFECTO):
        self.db = db
        self.ejecutando = False
        self._hilo = None
        self._ultimo_hash = ""
        database.iniciar(self.db)

    def iniciar(self, bloqueante: bool = True):
        self.ejecutando = True
        if bloqueante:
            self._bucle_monitoreo()
        else:
            self._hilo = threading.Thread(target=self._bucle_monitoreo, daemon=True)
            self._hilo.start()

    def detener(self):
        self.ejecutando = False
        if self._hilo and self._hilo.is_alive():
            self._hilo.join(timeout=1.0)

    def _bucle_monitoreo(self):
        cfg = cargar_config()
        intervalo = cfg.get("intervalo_sondeo", 0.5)

        while self.ejecutando:
            try:
                # Recargar configuración dinámica periódicamente
                cfg = cargar_config()
                modo = cfg.get("modo", "sanitizar")
                estrategia = cfg.get("estrategia_mascara", "asteriscos")
                notif_activa = cfg.get("notificaciones_activadas", True)

                if modo != "pausado":
                    actual = clipboard.obtener_texto()
                    if actual:
                        hash_actual = calcular_hash(actual)
                        if hash_actual != self._ultimo_hash:
                            self._ultimo_hash = hash_actual
                            nuevo, hallazgos = procesar(
                                actual,
                                modo=modo,
                                db=self.db,
                                origen="portapapeles",
                                estrategia=estrategia,
                            )
                            if hallazgos:
                                tipos = ", ".join(sorted({h.tipo for h in hallazgos}))
                                msg_log = (
                                    f"[!] {len(hallazgos)} secreto(s) interceptado(s): {tipos} "
                                    f"-> {'PROTEGIDO Y SANITIZADO' if modo == 'sanitizar' else 'MODO ALERTA'}"
                                )
                                print(msg_log)

                                if notif_activa:
                                    notificar(
                                        "ShadowGuard: Secreto detectado",
                                        f"{len(hallazgos)} secreto(s) [{tipos}] {'sanitizado(s)' if modo == 'sanitizar' else 'detectado(s)'}."
                                    )

                                if modo == "sanitizar":
                                    clipboard.establecer_texto(nuevo)
                                    self._ultimo_hash = calcular_hash(nuevo)

                time.sleep(intervalo)
            except KeyboardInterrupt:
                print("\n[ShadowGuard] Monitor detenido por el usuario.")
                self.ejecutando = False
                break
            except Exception as e:
                # Tolerancia a errores de lectura
                time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser(description="ShadowGuard - Monitor Inteligente de Portapapeles")
    ap.add_argument("--modo", choices=["sanitizar", "alerta", "pausado"], default=None)
    ap.add_argument("--db", default=database.DB_POR_DEFECTO)
    ap.add_argument("--intervalo", type=float, default=None)
    args = ap.parse_args()

    cfg = cargar_config()
    if args.modo:
        cfg["modo"] = args.modo
    if args.intervalo:
        cfg["intervalo_sondeo"] = args.intervalo
    guardar_config(cfg)

    print("=" * 60)
    print("   SHADOWGUARD - Escudo DLP Anti-fuga de Secretos en IA")
    print(f"   Modo activo: {cfg['modo'].upper()} | Estrategia: {cfg['estrategia_mascara']}")
    print("   Protegiendo portapapeles contra ChatGPT, Claude, Gemini...")
    print("   Presiona Ctrl+C para detener.")
    print("=" * 60)

    demonio = MonitorDemonio(db=args.db)
    demonio.iniciar(bloqueante=True)


if __name__ == "__main__":
    main()
