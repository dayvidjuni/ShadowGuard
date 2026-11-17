"""config.py - Gestión de configuración centralizada y persistente para ShadowGuard."""
import json
import os
from typing import Any, Dict

CONFIG_FILE = os.environ.get("SHADOWGUARD_CONFIG", "shadowguard_config.json")

CONFIG_POR_DEFECTO: Dict[str, Any] = {
    # Modo de funcionamiento: "sanitizar", "alerta", "pausado"
    "modo": "sanitizar",
    # Estrategia de máscara: "asteriscos", "etiqueta", "parcial"
    "estrategia_mascara": "asteriscos",
    # Intervalo de sondeo del portapapeles en segundos
    "intervalo_sondeo": 0.5,
    # Límite de caracteres a analizar para evitar congelamientos en textos gigantes
    "max_tamano_texto": 500000,
    # Notificaciones nativas de escritorio
    "notificaciones_activadas": True,
    # Umbrales de entropía de Shannon
    "entropia_activada": True,
    "umbral_base64": 4.5,
    "umbral_hex": 3.0,
    # Filtros de reducción de falsos positivos
    "ignorar_uuids": True,
    "ignorar_git_commits": True,
    "validar_luhn_tarjetas": True,
    # Lista blanca de términos/tokens permitidos (IDs de prueba o palabras seguras)
    "lista_blanca": [
        "00000000-0000-0000-0000-000000000000",
        "127.0.0.1",
        "localhost",
        "test-token-safe-1234567890",
    ],
    # Servidor Web Dashboard
    "host_dashboard": "127.0.0.1",
    "puerto_dashboard": 8000,
}


def cargar_config(ruta: str = CONFIG_FILE) -> Dict[str, Any]:
    """Carga la configuración desde el archivo JSON o crea la predeterminada."""
    if not os.path.exists(ruta):
        guardar_config(CONFIG_POR_DEFECTO, ruta)
        return dict(CONFIG_POR_DEFECTO)
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            datos = json.load(f)
            # Combinar con los valores por defecto por si faltan claves
            resultado = dict(CONFIG_POR_DEFECTO)
            resultado.update(datos)
            return resultado
    except Exception:
        return dict(CONFIG_POR_DEFECTO)


def guardar_config(nueva_config: Dict[str, Any], ruta: str = CONFIG_FILE) -> bool:
    """Guarda la configuración de forma segura en disco."""
    try:
        with open(ruta, "w", encoding="utf-8") as f:
            json.dump(nueva_config, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False
