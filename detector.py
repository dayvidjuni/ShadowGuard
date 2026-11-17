"""detector.py - Motor de detección de secretos por firmas regex y entropía de Shannon.

Incluye validadores matemáticos (Algoritmo de Luhn para tarjetas de crédito),
descarte de falsos positivos (UUIDs, commits de Git, hashes comunes) y lista blanca.
"""
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

from config import cargar_config


@dataclass(frozen=True)
class Hallazgo:
    inicio: int
    fin: int
    tipo: str
    metodo: str  # "regex" o "entropia"
    severidad: str = "Alta"  # "Critica", "Alta", "Media"


# Reglas de detección: (tipo, patrón regex, grupo valor, severidad)
REGLAS = [
    # Credenciales de Nube y Código
    ("Clave AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, "Critica"),
    ("Token GitHub", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", 0, "Critica"),
    ("Token GitHub Fine-Grained", r"\bgithub_pat_[0-9a-zA-Z_]{60,100}\b", 0, "Critica"),
    ("Clave OpenAI", r"\bsk-(?:proj-|admin-)?[A-Za-z0-9_-]{20,}\b", 0, "Critica"),
    ("Clave Google", r"\bAIza[0-9A-Za-z_-]{35}\b", 0, "Alta"),
    ("Token Slack", r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b", 0, "Alta"),
    ("Clave Stripe", r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b", 0, "Critica"),
    ("Token HuggingFace", r"\bhf_[a-zA-Z0-9]{34,}\b", 0, "Alta"),
    # Criptografía y Sesión
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0, "Alta"),
    (
        "Clave privada PEM",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?"
        r"(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----|\Z)",
        0,
        "Critica",
    ),
    # Bases de Datos e Infraestructura
    (
        "Cadena de conexion",
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|mssql)://[^:\s/]+:[^@\s]+@[^\s\"']+",
        0,
        "Critica",
    ),
    # Asignaciones de contraseñas y tokens en código
    (
        "Contrasena",
        r"(?i)(?<![A-Za-z])(?:password|passwd|pwd|secret|api_key|apikey|client_secret|auth_token)\s*[=:]\s*[\"']?([^\s\"',;]+)",
        1,
        "Alta",
    ),
    # Cabeceras de Autorización HTTP
    (
        "Token Bearer",
        r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{25,})\b",
        1,
        "Alta",
    ),
]

# Compilación previa de patrones
REGLAS_COMPILADAS = [(t, re.compile(p), g, s) for t, p, g, s in REGLAS]

# Patrones para filtrado de falsos positivos
RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
RE_GIT_COMMIT = re.compile(r"(?i)\b(?:commit\s+|commit:\s*|git\s+|tree\s+)([0-9a-f]{40})\b")
RE_TARJETA = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)

# Entropía
TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
ES_HEX = re.compile(r"^[0-9a-fA-F]+$")
LARGO_MIN = 20


def es_luhn_valido(numero: str) -> bool:
    """Valida un número con el algoritmo de Luhn (elimina falsos positivos de tarjetas)."""
    digitos = [int(c) for c in numero if c.isdigit()]
    if len(digitos) < 13 or len(digitos) > 19:
        return False
    checksum = 0
    inverso = digitos[::-1]
    for i, d in enumerate(inverso):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def shannon_entropy(s: str) -> float:
    """Calcula la entropía de Shannon en bits por símbolo."""
    if not s:
        return 0.0
    n = len(s)
    conteo = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in conteo.values())


def _solo_asteriscos(s: str) -> bool:
    return len(s) > 0 and set(s) <= {"*", "\r", "\n", " "}


def _hallazgos_tarjetas(texto: str):
    """Detecta números de tarjeta válidos según el algoritmo de Luhn."""
    for m in RE_TARJETA.finditer(texto):
        num = m.group()
        if es_luhn_valido(num):
            yield Hallazgo(m.start(), m.end(), "Tarjeta de credito", "regex", "Critica")


def _hallazgos_regex(texto: str):
    for tipo, patron, grupo, sev in REGLAS_COMPILADAS:
        for m in patron.finditer(texto):
            valor = m.group(grupo)
            if valor is None or _solo_asteriscos(valor):
                continue
            # Filtrar si la contraseña es un placeholder evidente de desarrollo
            if tipo == "Contrasena" and valor.lower() in {
                "null", "none", "true", "false", "undefined", "''", '""'
            }:
                continue
            yield Hallazgo(m.start(grupo), m.end(grupo), tipo, "regex", sev)


def _hallazgos_entropia(
    texto: str,
    u_b64: float,
    u_hex: float,
    ignorar_git: bool = True,
    ignorar_uuids: bool = True,
):
    # Obtener rangos de UUIDs si se van a ignorar
    uuid_spans = [m.span() for m in RE_UUID.finditer(texto)] if ignorar_uuids else []

    # Obtener rangos de commits de Git si se van a ignorar
    commit_spans = []
    if ignorar_git:
        for m in RE_GIT_COMMIT.finditer(texto):
            commit_spans.append(m.span(1))

    for m in TOKEN.finditer(texto):
        tok = m.group()
        largo = len(tok)
        if largo < LARGO_MIN or _solo_asteriscos(tok):
            continue

        # Evitar falsos positivos con UUIDs
        if uuid_spans and any(s <= m.start() and m.end() <= e for s, e in uuid_spans):
            continue

        # Evitar falsos positivos con Git Commits (40 hex precedido o no de commit)
        if ignorar_git:
            if any(s <= m.start() and m.end() <= e for s, e in commit_spans):
                continue
            # Si es exactamente 40 hex y no tiene prefijo claro de API key
            if largo == 40 and ES_HEX.match(tok):
                # Verificar contexto circundante para commits
                contexto = texto[max(0, m.start() - 15) : min(len(texto), m.end() + 15)].lower()
                if "commit" in contexto or "git" in contexto or "tree" in contexto:
                    continue

        umbral = u_hex if ES_HEX.match(tok) else u_b64
        if shannon_entropy(tok) > umbral:
            yield Hallazgo(
                m.start(),
                m.end(),
                "Cadena de alta entropia",
                "entropia",
                "Media",
            )


def _unir(hallazgos: List[Hallazgo]) -> List[Hallazgo]:
    """Une hallazgos solapados preservando tipo específico de regex y mayor severidad."""
    if not hallazgos:
        return []

    prioridad_sev = {"Critica": 3, "Alta": 2, "Media": 1}

    unidos = []
    for h in sorted(hallazgos, key=lambda x: (x.inicio, -x.fin)):
        if unidos and h.inicio < unidos[-1].fin:
            u = unidos[-1]
            nueva_sev = u.severidad
            if prioridad_sev.get(h.severidad, 1) > prioridad_sev.get(u.severidad, 1):
                nueva_sev = h.severidad

            # Prevalecer siempre regex sobre entropia para identificar el tipo específico
            if u.metodo == "regex":
                tipo_final = u.tipo
                metodo_final = u.metodo
            elif h.metodo == "regex":
                tipo_final = h.tipo
                metodo_final = h.metodo
            else:
                tipo_final = u.tipo
                metodo_final = u.metodo

            unidos[-1] = Hallazgo(
                u.inicio,
                max(u.fin, h.fin),
                tipo_final,
                metodo_final,
                nueva_sev,
            )
        else:
            unidos.append(h)
    return unidos


def detectar(
    texto: str,
    u_b64: Optional[float] = None,
    u_hex: Optional[float] = None,
    config_dict: Optional[dict] = None,
) -> List[Hallazgo]:
    """Detecta secretos en el texto combinando regex, algoritmos de validación y entropía.

    Aplica filtros de falsos positivos y lista blanca de forma automática.
    """
    if not texto:
        return []

    cfg = config_dict or cargar_config()

    # Protección contra denial of service (DoS) local por textos gigantes
    max_len = cfg.get("max_tamano_texto", 500000)
    if len(texto) > max_len:
        texto = texto[:max_len]

    u_b = u_b64 if u_b64 is not None else cfg.get("umbral_base64", 4.5)
    u_h = u_hex if u_hex is not None else cfg.get("umbral_hex", 3.0)
    usar_entropia = cfg.get("entropia_activada", True)
    ignorar_git = cfg.get("ignorar_git_commits", True)
    ignorar_uuids = cfg.get("ignorar_uuids", True)
    validar_luhn = cfg.get("validar_luhn_tarjetas", True)
    lista_blanca = set(cfg.get("lista_blanca", []))

    todos: List[Hallazgo] = list(_hallazgos_regex(texto))

    if validar_luhn:
        todos.extend(_hallazgos_tarjetas(texto))

    if usar_entropia:
        todos.extend(_hallazgos_entropia(texto, u_b, u_h, ignorar_git, ignorar_uuids))

    # Filtrar elementos en lista blanca
    if lista_blanca:
        filtrados = []
        for h in todos:
            valor = texto[h.inicio : h.fin]
            if valor not in lista_blanca:
                filtrados.append(h)
        todos = filtrados

    return _unir(todos)
