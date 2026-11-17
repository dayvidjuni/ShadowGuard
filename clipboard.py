"""clipboard.py - Acceso robusto, seguro y tolerante a fallos al portapapeles.

Estrategia multinivel con reintentos:
1. API nativa de Windows (ctypes: user32.dll / kernel32.dll) sin dependencias externas.
2. pyperclip si está instalado y disponible.
3. Fallback de comandos de plataforma (wl-copy, xclip, pbcopy).
4. Portapapeles virtual en memoria si el sistema operativo no concede acceso
   (por ejemplo, en entornos CI/CD sin interfaz gráfica o servicios sin ventana).
"""
import os
import platform
import subprocess
import sys
import time

_SISTEMA = platform.system().lower()

_TIENE_PYPERCLIP = False
try:
    import pyperclip
    _TIENE_PYPERCLIP = True
except Exception:
    _TIENE_PYPERCLIP = False

# Portapapeles virtual en memoria (útil en headless/CI o cuando el SO deniega acceso)
_PORTAPAPELES_MEMORIA = ""
_USAR_MEMORIA_FALLBACK = False


if _SISTEMA == "windows":
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE

    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    def _pegar_windows(intentos: int = 3, espera: float = 0.02) -> str:
        for _ in range(intentos):
            try:
                if user32.OpenClipboard(None):
                    try:
                        h_mem = user32.GetClipboardData(CF_UNICODETEXT)
                        if not h_mem:
                            return ""
                        p_mem = kernel32.GlobalLock(h_mem)
                        if not p_mem:
                            return ""
                        try:
                            val = ctypes.c_wchar_p(p_mem).value
                            return val or ""
                        finally:
                            kernel32.GlobalUnlock(h_mem)
                    finally:
                        user32.CloseClipboard()
            except Exception:
                pass
            time.sleep(espera)
        return ""

    def _copiar_windows(texto: str, intentos: int = 3, espera: float = 0.02) -> bool:
        if texto is None:
            texto = ""
        texto_bytes = (texto + "\0").encode("utf-16-le")
        tamano = len(texto_bytes)

        for _ in range(intentos):
            try:
                if user32.OpenClipboard(None):
                    try:
                        user32.EmptyClipboard()
                        h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, tamano)
                        if not h_mem:
                            return False
                        p_mem = kernel32.GlobalLock(h_mem)
                        if not p_mem:
                            return False
                        try:
                            ctypes.memmove(p_mem, texto_bytes, tamano)
                        finally:
                            kernel32.GlobalUnlock(h_mem)
                        res = user32.SetClipboardData(CF_UNICODETEXT, h_mem)
                        if res:
                            return True
                    finally:
                        user32.CloseClipboard()
            except Exception:
                pass
            time.sleep(espera)
        return False


def activar_modo_virtual(activo: bool = True):
    """Fuerza el uso del portapapeles virtual en memoria (ideal para tests/headless)."""
    global _USAR_MEMORIA_FALLBACK
    _USAR_MEMORIA_FALLBACK = activo


def obtener_texto() -> str:
    """Obtiene el texto del portapapeles con máxima tolerancia a fallos."""
    global _PORTAPAPELES_MEMORIA

    if _USAR_MEMORIA_FALLBACK:
        return _PORTAPAPELES_MEMORIA

    # 1. En Windows, intentar API nativa
    if _SISTEMA == "windows":
        try:
            val = _pegar_windows()
            if val:
                return val
        except Exception:
            pass

    # 2. Pyperclip
    if _TIENE_PYPERCLIP:
        try:
            val = pyperclip.paste()
            if isinstance(val, str) and val:
                return val
        except Exception:
            pass

    # 3. macOS
    if _SISTEMA == "darwin":
        try:
            p = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=0.5)
            if p.returncode == 0:
                return p.stdout
        except Exception:
            pass

    # 4. Linux
    if _SISTEMA == "linux":
        for cmd in [["wl-paste"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "-b", "-o"]]:
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=0.5)
                if p.returncode == 0:
                    return p.stdout
            except Exception:
                continue

    return _PORTAPAPELES_MEMORIA


def establecer_texto(texto: str) -> bool:
    """Escribe texto en el portapapeles de forma segura."""
    global _PORTAPAPELES_MEMORIA
    if texto is None:
        texto = ""
    _PORTAPAPELES_MEMORIA = texto

    if _USAR_MEMORIA_FALLBACK:
        return True

    exito = False

    # 1. En Windows
    if _SISTEMA == "windows":
        try:
            if _copiar_windows(texto):
                return True
        except Exception:
            pass

    # 2. Pyperclip
    if _TIENE_PYPERCLIP:
        try:
            pyperclip.copy(texto)
            exito = True
        except Exception:
            pass

    # 3. macOS
    if _SISTEMA == "darwin":
        try:
            p = subprocess.run(["pbcopy"], input=texto, text=True, timeout=0.5)
            if p.returncode == 0:
                return True
        except Exception:
            pass

    # 4. Linux
    if _SISTEMA == "linux":
        for cmd in [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "-b", "-i"]]:
            try:
                p = subprocess.run(cmd, input=texto, text=True, timeout=0.5)
                if p.returncode == 0:
                    return True
            except Exception:
                continue

    # Si ningún método del SO pudo (por permisos o sesión no interactiva), la memoria guardó el texto
    return exito or True
