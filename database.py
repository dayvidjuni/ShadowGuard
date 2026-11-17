"""database.py - Registro local de incidentes en SQLite (WAL, índices y cero secretos).

Garantía de privacidad: JAMÁS almacena el secreto en disco. Solo almacena metadata:
tipo de secreto, método de detección, severidad, longitud, acción tomada y origen.
"""
import csv
import io
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

DB_POR_DEFECTO = "shadowguard.db"


def _conn(ruta: str = DB_POR_DEFECTO) -> sqlite3.Connection:
    c = sqlite3.connect(ruta, timeout=10.0)
    c.row_factory = sqlite3.Row
    # Optimizaciones de rendimiento y concurrencia
    c.execute("PRAGMA journal_mode = WAL")
    c.execute("PRAGMA synchronous = NORMAL")
    c.execute("PRAGMA busy_timeout = 5000")
    return c


def iniciar(ruta: str = DB_POR_DEFECTO):
    """Crea la tabla e índices si no existen."""
    with _conn(ruta) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS incidentes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            tipo TEXT NOT NULL,
            metodo TEXT NOT NULL,
            severidad TEXT NOT NULL DEFAULT 'Alta',
            longitud INTEGER NOT NULL,
            accion TEXT NOT NULL,
            origen TEXT NOT NULL
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_inc_fecha ON incidentes(fecha)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_inc_tipo ON incidentes(tipo)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_inc_origen ON incidentes(origen)")


def registrar(
    tipo: str,
    metodo: str,
    longitud: int,
    accion: str,
    origen: str = "portapapeles",
    severidad: str = "Alta",
    ruta: str = DB_POR_DEFECTO,
):
    """Registra un incidente de forma segura y atómica."""
    with _conn(ruta) as c:
        c.execute(
            """INSERT INTO incidentes (fecha, tipo, metodo, severidad, longitud, accion, origen)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(timespec="seconds"),
                tipo,
                metodo,
                severidad,
                longitud,
                accion,
                origen,
            ),
        )


def historial(
    limite: int = 100,
    offset: int = 0,
    tipo: Optional[str] = None,
    busqueda: Optional[str] = None,
    ruta: str = DB_POR_DEFECTO,
) -> List[Dict[str, Any]]:
    """Devuelve el historial con soporte de filtros y paginación."""
    query = "SELECT * FROM incidentes WHERE 1=1"
    params = []

    if tipo and tipo != "todos":
        query += " AND tipo = ?"
        params.append(tipo)

    if busqueda:
        query += " AND (tipo LIKE ? OR origen LIKE ? OR accion LIKE ?)"
        termino = f"%{busqueda}%"
        params.extend([termino, termino, termino])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limite, offset])

    with _conn(ruta) as c:
        return [dict(r) for r in c.execute(query, tuple(params))]


def estadisticas(ruta: str = DB_POR_DEFECTO) -> Dict[str, Any]:
    """Estadísticas completas para el dashboard."""
    iniciar(ruta)
    with _conn(ruta) as c:
        total = c.execute("SELECT COUNT(*) FROM incidentes").fetchone()[0]
        hoy = c.execute(
            "SELECT COUNT(*) FROM incidentes WHERE fecha >= date('now','localtime')"
        ).fetchone()[0]

        # Últimos 7 días
        hace_7_dias = (datetime.now() - timedelta(days=7)).isoformat(timespec="seconds")
        semana = c.execute(
            "SELECT COUNT(*) FROM incidentes WHERE fecha >= ?", (hace_7_dias,)
        ).fetchone()[0]

        por_tipo = {
            r["tipo"]: r["n"]
            for r in c.execute(
                "SELECT tipo, COUNT(*) n FROM incidentes GROUP BY tipo ORDER BY n DESC"
            )
        }

        por_severidad = {
            r["severidad"]: r["n"]
            for r in c.execute(
                "SELECT severidad, COUNT(*) n FROM incidentes GROUP BY severidad ORDER BY n DESC"
            )
        }

        por_origen = {
            r["origen"]: r["n"]
            for r in c.execute(
                "SELECT origen, COUNT(*) n FROM incidentes GROUP BY origen ORDER BY n DESC LIMIT 5"
            )
        }

        por_accion = {
            r["accion"]: r["n"]
            for r in c.execute(
                "SELECT accion, COUNT(*) n FROM incidentes GROUP BY accion ORDER BY n DESC"
            )
        }

    return {
        "total": total,
        "hoy": hoy,
        "semana": semana,
        "por_tipo": por_tipo,
        "por_severidad": por_severidad,
        "por_origen": por_origen,
        "por_accion": por_accion,
    }


def vaciar_historial(ruta: str = DB_POR_DEFECTO):
    """Elimina todos los registros de incidentes."""
    with _conn(ruta) as c:
        c.execute("DELETE FROM incidentes")


def purgar_antiguos(dias: int = 90, ruta: str = DB_POR_DEFECTO):
    """Elimina incidentes con más de N días para mantener la BD ligera."""
    limite = (datetime.now() - timedelta(days=dias)).isoformat(timespec="seconds")
    with _conn(ruta) as c:
        c.execute("DELETE FROM incidentes WHERE fecha < ?", (limite,))


def exportar_csv(ruta: str = DB_POR_DEFECTO) -> str:
    """Exporta todo el historial a formato CSV."""
    with _conn(ruta) as c:
        filas = c.execute("SELECT id, fecha, tipo, metodo, severidad, longitud, accion, origen FROM incidentes ORDER BY id DESC").fetchall()
    salida = io.StringIO()
    writer = csv.writer(salida)
    writer.writerow(["ID", "Fecha", "Tipo", "Metodo", "Severidad", "Longitud", "Accion", "Origen"])
    for f in filas:
        writer.writerow(list(f))
    return salida.getvalue()
