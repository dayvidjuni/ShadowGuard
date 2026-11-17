"""proxy_addon.py (opcional) - Complemento mitmproxy: sanitiza peticiones hacia dominios de IA.

Uso:  mitmproxy -s proxy_addon.py     (requiere instalar el certificado de mitmproxy)
"""
import database
from detector import detectar
from sanitizer import sanitizar

DOMINIOS_IA = (
    "chatgpt.com",
    "chat.openai.com",
    "api.openai.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "claude.ai",
    "api.anthropic.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "deepseek.com",
    "api.deepseek.com",
    "mistral.ai",
    "api.mistral.ai",
    "groq.com",
)


class ShadowGuardProxy:
    def __init__(self):
        database.iniciar()

    def request(self, flow):
        host = flow.request.pretty_host
        if not any(host == d or host.endswith("." + d) for d in DOMINIOS_IA):
            return
        texto = flow.request.get_text(strict=False)
        if not texto:
            return
        hallazgos = detectar(texto)
        if hallazgos:
            for h in hallazgos:
                database.registrar(
                    tipo=h.tipo,
                    metodo=h.metodo,
                    longitud=h.fin - h.inicio,
                    accion="sanitizado",
                    origen=f"proxy:{host}",
                    severidad=h.severidad,
                )
            flow.request.set_text(sanitizar(texto, hallazgos))


addons = [ShadowGuardProxy()]
