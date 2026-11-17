"""sanitizer.py - Sanitización configurable y segura de secretos detectados.

Soporta múltiples estrategias:
- "asteriscos": Conserva la longitud y saltos de línea (ideal para no romper indentación).
- "parcial": Conserva prefijo y sufijo visible (ej. AKIA************123).
- "etiqueta": Sustituye por [PROTEGIDO: <TIPO>].
"""
from typing import List
from config import cargar_config


def sanitizar(texto: str, hallazgos, estrategia: str = None) -> str:
    """Sanitiza el texto reemplazando las zonas de secretos según la estrategia elegida.

    Procesa de derecha a izquierda para preservar los índices de caracteres.
    """
    if not texto or not hallazgos:
        return texto

    if estrategia is None:
        cfg = cargar_config()
        estrategia = cfg.get("estrategia_mascara", "asteriscos")

    # Ordenar de mayor a menor posición de inicio para no invalidar offsets
    for h in sorted(hallazgos, key=lambda x: x.inicio, reverse=True):
        zona = texto[h.inicio : h.fin]

        if estrategia == "etiqueta":
            mascara = f"[PROTEGIDO: {h.tipo}]"
        elif estrategia == "parcial" and len(zona) >= 12:
            visible_ini = min(4, len(zona) // 4)
            visible_fin = min(4, len(zona) // 4)
            medio_len = len(zona) - visible_ini - visible_fin
            mascara = zona[:visible_ini] + ("*" * medio_len) + zona[-visible_fin:]
        else:  # "asteriscos" por defecto
            mascara = "".join(c if c in "\r\n" else "*" for c in zona)

        texto = texto[: h.inicio] + mascara + texto[h.fin :]

    return texto
