# 🛡️ ShadowGuard 2.0
> **Escudo DLP local anti-fuga de secretos en Inteligencia Artificial (ChatGPT, Claude, Gemini, DeepSeek, etc.)**

ShadowGuard vigila y protege en tiempo real el contenido de tu portapapeles y tráfico de red, interceptando y sanitizando automáticamente claves de API, contraseñas, tokens y credenciales privadas antes de que las pegues por error en un chatbot o modelo de IA.

---

## 🚀 Inicio Rápido (Para Cualquier Usuario)

No necesitas conocimientos técnicos para protegerte:

### En Windows:
1. Haz **doble clic en `iniciar.bat`**.
2. ¡Listo! ShadowGuard activará la protección en segundo plano y abrirá tu **Centro de Control Web** en tu navegador (`http://127.0.0.1:8000`).

### En Linux o macOS:
```bash
chmod +x iniciar.sh
./iniciar.sh
```

---

## ✨ Características Principales

### 🔒 1. Detección Ampliada de Secretos (Más de 20 Tipos)
- **Nube e Infraestructura:** Claves AWS (`AKIA...` y `ASIA...`), Google Cloud / Gemini API (`AIza...`), Azure Connection Strings, Cadenas de conexión (PostgreSQL, MySQL, MongoDB, Redis, MSSQL).
- **IA y Modelos:** Claves OpenAI (`sk-`, `sk-proj-`, `sk-admin-`), Tokens HuggingFace (`hf_...`).
- **Control de Versiones y Colaboración:** Tokens GitHub clásicos (`ghp_`, `gho_`, etc.) y Fine-Grained PATs (`github_pat_`), Tokens de Slack (`xoxb-`, `xoxp-`), Tokens de Discord.
- **Fintech y Pagos:** Claves Stripe (`sk_live_`, `rk_live_`), Tarjetas de Crédito con **validación matemática por Algoritmo de Luhn** (evita falsos positivos en números aleatorios).
- **Criptografía y Sesiones:** Claves privadas PEM (RSA, EC, OPENSSH, DSA, PGP), Tokens JWT (`eyJ...`), Tokens Bearer HTTP, contraseñas y secretos asignados en código (`password=`, `api_key=`, `secret=`).
- **Entropía de Shannon:** Detección de cadenas aleatorias no estructuradas de alta densidad de información.

### 🎯 2. Reducción Inteligente de Falsos Positivos
- **Filtro de UUIDs:** Ignora identificadores únicos estándar (`123e4567-e89b...`).
- **Filtro de Git Commits:** Reconoce hashes SHA-1 legítimos de control de versiones y no los bloquea indebidamente.
- **Lista Blanca (Allowlist):** Configura tokens seguros de desarrollo o pruebas para que nunca se alteren.

### ⚡ 3. Máximo Rendimiento y Cero Fricción
- **Tiempo medio de análisis:** Menos de **0.2 milisegundos** por texto.
- **Bajo consumo de recursos:** Monitoreo optimizado con hashes LRU (no recalcula si el texto no ha cambiado).
- **Límite DoS:** Protege la memoria contra congelamientos si copias archivos gigantescos de cientos de megabytes.

### 🛡️ 4. Privacidad y Seguridad Absoluta
- **Garantía Cero Almacenamiento:** **JAMÁS se almacena el secreto en disco ni en base de datos**. Solo se registra metadatos de auditoría: fecha, categoría del secreto, método de detección, longitud y acción tomada.
- **Base de Datos SQLite en modo WAL:** Alto rendimiento de lecturas y escrituras concurrentes sin bloqueos.
- **Prevención XSS:** Sanitización estricta de salida en el panel de control.

### 🧪 5. Probador Interactivo en Vivo (Playground)
- Accede a la pestaña **🧪 Probador en Vivo** en el panel web.
- Pega cualquier fragmento de código o prompt y observa en tiempo real los secretos detectados, su severidad (Crítica, Alta, Media) y la vista sanitizada con un botón para copiar el texto limpio.

### 🔔 6. Notificaciones Nativas de Escritorio
- Alerta visual inmediata en tu sistema operativo cuando un secreto es interceptado y sanitizado, sin necesidad de tener una consola abierta.

---

## 🛠️ Modos de Funcionamiento

Puedes cambiar el modo desde el **Panel Web** con un solo clic o por línea de comandos:

| Modo | Descripción |
|---|---|
| **🛡️ Sanitizar (Recomendado)** | Detecta el secreto y lo reemplaza inmediatamente en el portapapeles para que pegues una versión segura. |
| **⚠️ Solo Alerta** | Registra el incidente y te notifica, pero no modifica el contenido de tu portapapeles. |
| **⏸️ Pausado** | Suspende temporalmente la vigilancia sin cerrar el programa. |

### Estrategias de Sanitización Disponibles:
1. **Asteriscos (`asteriscos`)**: Sustituye cada carácter del secreto por `*`, preservando saltos de línea y longitud exacta (ideal para no romper indentación de código).
2. **Parcial (`parcial`)**: Muestra los primeros 4 y últimos 4 caracteres (ej. `AKIA************1234`) para que reconozcas cuál clave era.
3. **Etiqueta (`etiqueta`)**: Reemplaza el secreto por una etiqueta descriptiva (ej. `[PROTEGIDO: Clave AWS]`).

---

## 💻 Uso Avanzado (CLI)

```bash
# Iniciar todo (Monitor + Dashboard Web + Apertura automática del navegador)
python main.py

# Iniciar solo el monitor en segundo plano
python main.py --solo-monitor --modo sanitizar

# Iniciar solo el panel web en un puerto específico
python main.py --solo-web --puerto 8080

# Ejecutar el monitor clásico
python monitor.py --modo sanitizar --intervalo 0.5
```

---

## 🧪 Pruebas y Evaluación

Para ejecutar la suite de pruebas automatizadas:
```bash
python -m pytest -v
```

Para evaluar métricas de precisión, detección y tiempo medio de respuesta:
```bash
python evaluate.py
```

Resultados de evaluación del motor:
- **Precisión:** `100.0%` (0 falsos positivos en texto ordinario)
- **Tasa de Detección:** `100.0%`
- **Tiempo medio de inferencia:** `~0.18 ms` por muestra.

---

## 📦 Estructura del Proyecto

```text
shadowguard/
├── clipboard.py          # Manejo de portapapeles nativo (Windows ctypes / fallback seguro)
├── config.py             # Configuración centralizada persistente (shadowguard_config.json)
├── database.py           # SQLite optimizado con WAL, índices, exportación CSV y privacidad
├── detector.py           # Motor de reglas regex, validación Luhn y entropía de Shannon
├── evaluate.py           # Dataset sintético de benchmark y cálculo de métricas
├── monitor.py            # Demonio de vigilancia continua del portapapeles
├── notifier.py           # Notificaciones de escritorio multiplataforma
├── proxy_addon.py        # Complemento opcional para inspección mitmproxy
├── requirements.txt      # Dependencias del proyecto
├── sanitizer.py          # Motor de sanitización (asteriscos, parcial, etiquetas)
├── test_shadowguard.py   # Suite de tests exhaustivos (13 tests unitarios y de integración)
├── main.py               # Launcher unificado con interfaz gráfica web
├── iniciar.bat           # Acceso rápido en 1 clic para Windows
├── iniciar.sh            # Acceso rápido para Linux/macOS
└── dashboard/
    └── main.py           # API REST FastAPI + Centro de Control Web interactivo
```

---

## 📄 Licencia
Proyecto distribuido bajo licencia MIT. Desarrollado para mantener la privacidad y seguridad frente al uso de herramientas de Inteligencia Artificial.
