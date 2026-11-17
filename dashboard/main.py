"""dashboard/main.py - Panel de control web y API REST para ShadowGuard.

Ejecución:
    uvicorn dashboard.main:app --reload
o mediante el launcher unificado:
    python main.py
"""
import os
import sys
from typing import Optional

# Asegurar path para importar módulos raíz
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

import config
import database
from detector import detectar
from sanitizer import sanitizar

DB = os.environ.get("SHADOWGUARD_DB", database.DB_POR_DEFECTO)
database.iniciar(DB)

app = FastAPI(
    title="ShadowGuard DLP",
    description="Panel de Protección contra Fuga de Secretos en Modelos de IA",
    version="2.0.0",
)

# CORS seguro
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class PruebaTextoRequest(BaseModel):
    texto: str = Field(..., max_length=1000000)
    estrategia: Optional[str] = "asteriscos"


class ActualizarConfigRequest(BaseModel):
    modo: Optional[str] = None
    estrategia_mascara: Optional[str] = None
    notificaciones_activadas: Optional[bool] = None
    entropia_activada: Optional[bool] = None
    umbral_base64: Optional[float] = None
    umbral_hex: Optional[float] = None


@app.get("/api/stats")
def obtener_estadisticas():
    return database.estadisticas(DB)


@app.get("/api/incidents")
def obtener_incidentes(
    limite: int = 100,
    offset: int = 0,
    tipo: Optional[str] = None,
    busqueda: Optional[str] = None,
):
    return database.historial(
        limite=limite, offset=offset, tipo=tipo, busqueda=busqueda, ruta=DB
    )


@app.post("/api/test")
def probar_texto(req: PruebaTextoRequest):
    """Playground en vivo: analiza un texto sin registrar incidentes y devuelve la vista sanitizada."""
    hallazgos = detectar(req.texto)
    texto_sanitizado = sanitizar(req.texto, hallazgos, req.estrategia)
    resultado = [
        {
            "tipo": h.tipo,
            "metodo": h.metodo,
            "severidad": h.severidad,
            "inicio": h.inicio,
            "fin": h.fin,
            "longitud": h.fin - h.inicio,
        }
        for h in hallazgos
    ]
    return {
        "total_detectados": len(resultado),
        "hallazgos": resultado,
        "texto_sanitizado": texto_sanitizado,
    }


@app.get("/api/config")
def obtener_configuracion():
    return config.cargar_config()


@app.post("/api/config")
def actualizar_configuracion(req: ActualizarConfigRequest):
    cfg = config.cargar_config()
    if req.modo is not None:
        cfg["modo"] = req.modo
    if req.estrategia_mascara is not None:
        cfg["estrategia_mascara"] = req.estrategia_mascara
    if req.notificaciones_activadas is not None:
        cfg["notificaciones_activadas"] = req.notificaciones_activadas
    if req.entropia_activada is not None:
        cfg["entropia_activada"] = req.entropia_activada
    if req.umbral_base64 is not None:
        cfg["umbral_base64"] = req.umbral_base64
    if req.umbral_hex is not None:
        cfg["umbral_hex"] = req.umbral_hex
    config.guardar_config(cfg)
    return {"status": "ok", "config": cfg}


@app.post("/api/clear")
def vaciar_historial():
    database.vaciar_historial(DB)
    return {"status": "ok", "mensaje": "Historial vaciado"}


@app.get("/api/export/csv")
def exportar_csv():
    contenido = database.exportar_csv(DB)
    return Response(
        content=contenido,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=shadowguard_incidentes.csv"},
    )


PAGINA_HTML = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShadowGuard - Centro de Seguridad y Control DLP</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --card-hover: #1c2128;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #2f81f7;
      --accent-hover: #388bfd;
      --critica: #f85149;
      --alta: #d29922;
      --media: #e3b341;
      --success: #238636;
      --badge-bg: #21262d;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f6f8fa;
        --card: #ffffff;
        --card-hover: #f3f4f6;
        --border: #d0d7de;
        --text: #1f2328;
        --muted: #656d76;
        --accent: #0969da;
        --accent-hover: #0860ca;
        --critica: #cf222e;
        --alta: #9a6700;
        --media: #bf8700;
        --success: #1a7f37;
        --badge-bg: #eaeef2;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      gap: 16px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-logo {
      font-size: 28px;
      background: linear-gradient(135deg, #2f81f7, #238636);
      width: 48px;
      height: 48px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 12px;
      color: white;
    }
    .brand h1 { font-size: 24px; font-weight: 700; }
    .brand p { font-size: 13px; color: var(--muted); }
    .status-bar {
      display: flex;
      align-items: center;
      gap: 12px;
      background: var(--card);
      padding: 6px 14px;
      border-radius: 30px;
      border: 1px solid var(--border);
    }
    .status-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 8px var(--success);
    }
    .status-dot.alerta { background: var(--alta); box-shadow: 0 0 8px var(--alta); }
    .status-dot.pausado { background: var(--muted); box-shadow: none; }
    .mode-select {
      background: transparent;
      border: none;
      color: var(--text);
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      outline: none;
    }
    .mode-select option { background: var(--card); color: var(--text); }
    .grid-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .stat-val { font-size: 32px; font-weight: 700; color: var(--accent); }
    .stat-label { font-size: 13px; color: var(--muted); font-weight: 500; }
    .tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    .tab-btn {
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      padding: 10px 16px;
      color: var(--muted);
      font-weight: 600;
      cursor: pointer;
      font-size: 14px;
    }
    .tab-btn.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }
    .section-content { display: none; }
    .section-content.active { display: block; }
    /* Playground */
    .playground-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    @media (max-width: 800px) { .playground-grid { grid-template-columns: 1fr; } }
    textarea {
      width: 100%;
      height: 200px;
      padding: 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-family: monospace;
      font-size: 13px;
      resize: vertical;
      outline: none;
    }
    textarea:focus { border-color: var(--accent); }
    .btn {
      background: var(--accent);
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
    }
    .btn:hover { background: var(--accent-hover); }
    .btn-secondary { background: var(--badge-bg); color: var(--text); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--card-hover); }
    .btn-danger { background: var(--critica); }
    .btn-danger:hover { opacity: 0.9; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge-critica { background: rgba(248, 81, 73, 0.2); color: var(--critica); border: 1px solid var(--critica); }
    .badge-alta { background: rgba(210, 153, 34, 0.2); color: var(--alta); border: 1px solid var(--alta); }
    .badge-media { background: rgba(227, 179, 65, 0.2); color: var(--media); border: 1px solid var(--media); }
    .badge-success { background: rgba(35, 134, 54, 0.2); color: var(--success); border: 1px solid var(--success); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    tr:hover { background: var(--card-hover); }
    .filter-bar {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
      align-items: center;
    }
    .search-input {
      padding: 8px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 13px;
      min-width: 250px;
    }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; }
    .form-control {
      padding: 8px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 13px;
    }
  </style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="brand-logo">🛡️</div>
      <div>
        <h1>ShadowGuard</h1>
        <p>Escudo DLP: Detección y sanitización local de secretos en IA</p>
      </div>
    </div>
    <div class="status-bar">
      <div id="statusDot" class="status-dot"></div>
      <label for="modoSelect" style="font-size:12px; color:var(--muted)">Modo:</label>
      <select id="modoSelect" class="mode-select" onchange="cambiarModo(this.value)">
        <option value="sanitizar">🛡️ Sanitizar Portapapeles</option>
        <option value="alerta">⚠️ Solo Alerta (Sin modificar)</option>
        <option value="pausado">⏸️ Pausado</option>
      </select>
    </div>
  </header>

  <!-- Tarjetas de métricas -->
  <div class="grid-stats">
    <div class="card">
      <div class="stat-val" id="statTotal">0</div>
      <div class="stat-label">Incidentes Totales Evitados</div>
    </div>
    <div class="card">
      <div class="stat-val" id="statHoy">0</div>
      <div class="stat-label">Bloqueados Hoy</div>
    </div>
    <div class="card">
      <div class="stat-val" id="statSemana">0</div>
      <div class="stat-label">Últimos 7 días</div>
    </div>
    <div class="card">
      <div class="stat-val" style="color:var(--success)" id="statPrivacidad">100%</div>
      <div class="stat-label">Privacidad (Cero secretos en disco)</div>
    </div>
  </div>

  <!-- Pestañas de navegación -->
  <div class="tabs">
    <button class="tab-btn active" onclick="cambiarTab('incidentes', this)">📋 Historial de Incidentes</button>
    <button class="tab-btn" onclick="cambiarTab('playground', this)">🧪 Probador en Vivo (Playground)</button>
    <button class="tab-btn" onclick="cambiarTab('configuracion', this)">⚙️ Configuración</button>
  </div>

  <!-- Pestaña 1: Historial -->
  <div id="tab-incidentes" class="section-content active">
    <div class="card">
      <div class="filter-bar">
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <input type="text" id="busquedaInput" class="search-input" placeholder="Buscar por tipo, origen o acción..." oninput="filtrarIncidentes()">
          <select id="filtroTipo" class="form-control" onchange="filtrarIncidentes()">
            <option value="todos">Todos los tipos</option>
          </select>
        </div>
        <div style="display:flex; gap:8px;">
          <a href="/api/export/csv" class="btn btn-secondary">📥 Exportar CSV</a>
          <button onclick="limpiarHistorial()" class="btn btn-danger">🗑️ Limpiar Historial</button>
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Tipo de Secreto</th>
              <th>Método</th>
              <th>Severidad</th>
              <th>Longitud</th>
              <th>Acción</th>
              <th>Origen</th>
            </tr>
          </thead>
          <tbody id="tablaIncidentes">
            <tr><td colspan="7" style="text-align:center; color:var(--muted)">Cargando incidentes...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Pestaña 2: Playground -->
  <div id="tab-playground" class="section-content">
    <div class="card">
      <h3 style="margin-bottom:8px">🧪 Probador y Sanitizador de Texto en Tiempo Real</h3>
      <p style="color:var(--muted); font-size:13px; margin-bottom:16px">
        Pega cualquier texto o código para verificar qué secretos detecta ShadowGuard y cómo se sanitizan antes de enviarlos a ChatGPT, Claude o Gemini.
      </p>
      <div class="playground-grid">
        <div>
          <label style="font-weight:600; font-size:13px; margin-bottom:6px; display:block">Texto Original:</label>
          <textarea id="playTexto" placeholder="Pega aquí código con tokens o claves para probar... (ej. sk-proj-1234567890abcdef1234567890 o AKIAIOSFODNN7EXAMPLE)"></textarea>
          <div style="margin-top:12px; display:flex; gap:8px;">
            <button onclick="analizarTextoPlayground()" class="btn">🔍 Analizar y Sanitizar</button>
            <button onclick="document.getElementById('playTexto').value=''; analizarTextoPlayground();" class="btn btn-secondary">Limpiar</button>
          </div>
        </div>
        <div>
          <label style="font-weight:600; font-size:13px; margin-bottom:6px; display:block">Resultado Protegido / Sanitizado:</label>
          <textarea id="playResultado" readonly placeholder="Aquí aparecerá el texto protegido..."></textarea>
          <div style="margin-top:12px;">
            <button onclick="copiarSanitizado()" class="btn btn-secondary">📋 Copiar Texto Seguro</button>
          </div>
        </div>
      </div>
      <div id="playHallazgos" style="margin-top:20px"></div>
    </div>
  </div>

  <!-- Pestaña 3: Configuración -->
  <div id="tab-configuracion" class="section-content">
    <div class="card" style="max-width:700px">
      <h3 style="margin-bottom:16px">⚙️ Opciones de Seguridad y Detección</h3>
      <div class="form-group">
        <label>Estrategia de Enmascaramiento:</label>
        <select id="cfgEstrategia" class="form-control" style="width:100%" onchange="guardarOpciones()">
          <option value="asteriscos">Asteriscos (Mantiene tamaño y formato de código)</option>
          <option value="parcial">Parcial (Conserva prefijo y sufijo visible)</option>
          <option value="etiqueta">Etiqueta [PROTEGIDO: &lt;Tipo&gt;]</option>
        </select>
      </div>
      <div class="form-group">
        <label>
          <input type="checkbox" id="cfgNotificaciones" onchange="guardarOpciones()"> Notificaciones de escritorio nativas al detectar secretos
        </label>
      </div>
      <div class="form-group">
        <label>
          <input type="checkbox" id="cfgEntropia" onchange="guardarOpciones()"> Activar detección por alta entropía de Shannon (para secretos sin prefijo)
        </label>
      </div>
      <div class="form-group">
        <label>Umbral Entropía Base64:</label>
        <input type="number" step="0.1" id="cfgUb64" class="form-control" style="width:100%" onchange="guardarOpciones()">
      </div>
      <div class="form-group">
        <label>Umbral Entropía Hexadecimal:</label>
        <input type="number" step="0.1" id="cfgUhex" class="form-control" style="width:100%" onchange="guardarOpciones()">
      </div>
      <div id="cfgGuardadoMsg" style="color:var(--success); font-size:13px; display:none; margin-top:8px">✓ Configuración actualizada con éxito</div>
    </div>
  </div>
</div>

<script>
// Escape HTML seguro contra XSS
function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function cambiarTab(tabName, btn) {
  document.querySelectorAll('.section-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + tabName).classList.add('active');
  btn.classList.add('active');
}

async function cargarDatos() {
  try {
    const [resStats, resInc, resCfg] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/incidents?limite=100'),
      fetch('/api/config')
    ]);
    const stats = await resStats.json();
    const incs = await resInc.json();
    const cfg = await resCfg.json();

    document.getElementById('statTotal').textContent = stats.total || 0;
    document.getElementById('statHoy').textContent = stats.hoy || 0;
    document.getElementById('statSemana').textContent = stats.semana || 0;

    // Selector de modo y dot
    const modoSelect = document.getElementById('modoSelect');
    modoSelect.value = cfg.modo || 'sanitizar';
    actualizarDot(cfg.modo);

    // Tipos para el filtro
    const filtro = document.getElementById('filtroTipo');
    const actualVal = filtro.value;
    const tipos = Object.keys(stats.por_tipo || {});
    filtro.innerHTML = '<option value="todos">Todos los tipos</option>' +
      tipos.map(t => `<option value="${esc(t)}">${esc(t)} (${stats.por_tipo[t]})</option>`).join('');
    filtro.value = actualVal;

    renderizarIncidentes(incs);

    // Rellenar formulario de configuración
    document.getElementById('cfgEstrategia').value = cfg.estrategia_mascara || 'asteriscos';
    document.getElementById('cfgNotificaciones').checked = !!cfg.notificaciones_activadas;
    document.getElementById('cfgEntropia').checked = !!cfg.entropia_activada;
    document.getElementById('cfgUb64').value = cfg.umbral_base64 || 4.5;
    document.getElementById('cfgUhex').value = cfg.umbral_hex || 3.0;
  } catch (e) {
    console.error("Error cargando datos:", e);
  }
}

function actualizarDot(modo) {
  const dot = document.getElementById('statusDot');
  dot.className = 'status-dot';
  if (modo === 'alerta') dot.classList.add('alerta');
  else if (modo === 'pausado') dot.classList.add('pausado');
}

function renderizarIncidentes(lista) {
  const tbody = document.getElementById('tablaIncidentes');
  if (!lista || lista.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:24px">No hay incidentes registrados aún. ¡El sistema está vigilando!</td></tr>';
    return;
  }
  tbody.innerHTML = lista.map(r => {
    let sevBadge = 'badge-media';
    if (r.severidad === 'Critica') sevBadge = 'badge-critica';
    else if (r.severidad === 'Alta') sevBadge = 'badge-alta';
    return `
      <tr>
        <td style="color:var(--muted)">${esc(r.fecha)}</td>
        <td><b>${esc(r.tipo)}</b></td>
        <td><code>${esc(r.metodo)}</code></td>
        <td><span class="badge ${sevBadge}">${esc(r.severidad || 'Alta')}</span></td>
        <td>${esc(r.longitud)} chars</td>
        <td><span class="badge ${r.accion === 'sanitizado' ? 'badge-success' : 'badge-alta'}">${esc(r.accion)}</span></td>
        <td><code>${esc(r.origen)}</code></td>
      </tr>
    `;
  }).join('');
}

async function filtrarIncidentes() {
  const q = document.getElementById('busquedaInput').value;
  const t = document.getElementById('filtroTipo').value;
  let url = `/api/incidents?limite=100`;
  if (t && t !== 'todos') url += `&tipo=${encodeURIComponent(t)}`;
  if (q) url += `&busqueda=${encodeURIComponent(q)}`;
  const res = await fetch(url);
  const data = await res.json();
  renderizarIncidentes(data);
}

async function cambiarModo(nuevoModo) {
  await fetch('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ modo: nuevoModo })
  });
  actualizarDot(nuevoModo);
}

async function guardarOpciones() {
  const est = document.getElementById('cfgEstrategia').value;
  const notif = document.getElementById('cfgNotificaciones').checked;
  const entr = document.getElementById('cfgEntropia').checked;
  const ub = parseFloat(document.getElementById('cfgUb64').value);
  const uh = parseFloat(document.getElementById('cfgUhex').value);

  await fetch('/api/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      estrategia_mascara: est,
      notificaciones_activadas: notif,
      entropia_activada: entr,
      umbral_base64: ub,
      umbral_hex: uh
    })
  });
  const msg = document.getElementById('cfgGuardadoMsg');
  msg.style.display = 'block';
  setTimeout(() => { msg.style.display = 'none'; }, 2000);
}

async function limpiarHistorial() {
  if (confirm("¿Estás seguro de que deseas vaciar el historial de incidentes?")) {
    await fetch('/api/clear', { method: 'POST' });
    cargarDatos();
  }
}

async function analizarTextoPlayground() {
  const txt = document.getElementById('playTexto').value;
  const est = document.getElementById('cfgEstrategia').value || 'asteriscos';
  if (!txt) {
    document.getElementById('playResultado').value = '';
    document.getElementById('playHallazgos').innerHTML = '';
    return;
  }
  const res = await fetch('/api/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ texto: txt, estrategia: est })
  });
  const data = await res.json();
  document.getElementById('playResultado').value = data.texto_sanitizado;

  const divH = document.getElementById('playHallazgos');
  if (data.total_detectados === 0) {
    divH.innerHTML = '<div style="color:var(--success); font-weight:600">✓ No se detectaron secretos ni credenciales en este fragmento. Seguro para enviar.</div>';
  } else {
    divH.innerHTML = `<h4 style="margin-bottom:8px">⚠️ ${data.total_detectados} secreto(s) detectado(s):</h4>` +
      data.hallazgos.map(h => `
        <div style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:8px 12px; margin-bottom:6px; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <b>${esc(h.tipo)}</b> (${esc(h.metodo)})
            <span style="color:var(--muted); font-size:12px; margin-left:8px">Posición: ${h.inicio} a ${h.fin} (${h.longitud} chars)</span>
          </div>
          <span class="badge ${h.severidad === 'Critica' ? 'badge-critica' : 'badge-alta'}">${esc(h.severidad)}</span>
        </div>
      `).join('');
  }
}

function copiarSanitizado() {
  const t = document.getElementById('playResultado');
  t.select();
  navigator.clipboard.writeText(t.value);
  alert("Texto sanitizado copiado al portapapeles.");
}

cargarDatos();
setInterval(cargarDatos, 4000);
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def inicio():
    return PAGINA_HTML
