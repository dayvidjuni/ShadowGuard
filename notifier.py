"""notifier.py - Notificaciones de escritorio para alertar al usuario de incidentes."""
import os
import platform
import subprocess
import threading
import time

_SISTEMA = platform.system().lower()
_ULTIMA_NOTIFICACION = 0.0
_COOLDOWN_SEGUNDOS = 2.0  # Evita saturar con alertas sucesivas


def _lanzar_notificacion_windows(titulo: str, mensaje: str):
    """Muestra notificación en Windows usando PowerShell de forma asíncrona."""
    # Escapar comillas simples
    tit = titulo.replace("'", "''")
    msg = mensaje.replace("'", "''")
    ps_script = f"""
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
    $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
    $textNodes = $xml.GetElementsByTagName('text')
    $textNodes.Item(0).AppendChild($xml.CreateTextNode('{tit}')) > $null
    $textNodes.Item(1).AppendChild($xml.CreateTextNode('{msg}')) > $null
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ShadowGuard')
    $notification = [Windows.UI.Notifications.ToastNotification]::new($xml)
    $notifier.Show($notification)
    """
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
    except Exception:
        pass


def _lanzar_notificacion_macos(titulo: str, mensaje: str):
    tit = titulo.replace('"', '\\"')
    msg = mensaje.replace('"', '\\"')
    try:
        subprocess.run(
            ["osascript", "-e", f'display notification "{msg}" with title "{tit}"'],
            capture_output=True,
            timeout=2
        )
    except Exception:
        pass


def _lanzar_notificacion_linux(titulo: str, mensaje: str):
    try:
        subprocess.run(["notify-send", titulo, mensaje], capture_output=True, timeout=2)
    except Exception:
        pass


def notificar(titulo: str, mensaje: str):
    """Envía una notificación de escritorio sin bloquear el hilo principal."""
    global _ULTIMA_NOTIFICACION
    ahora = time.time()
    if ahora - _ULTIMA_NOTIFICACION < _COOLDOWN_SEGUNDOS:
        return
    _ULTIMA_NOTIFICACION = ahora

    def _tarea():
        if _SISTEMA == "windows":
            _lanzar_notificacion_windows(titulo, mensaje)
        elif _SISTEMA == "darwin":
            _lanzar_notificacion_macos(titulo, mensaje)
        elif _SISTEMA == "linux":
            _lanzar_notificacion_linux(titulo, mensaje)

    t = threading.Thread(target=_tarea, daemon=True)
    t.start()
