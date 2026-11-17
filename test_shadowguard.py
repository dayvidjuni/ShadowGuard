import os
import clipboard
import config
import database
from detector import detectar, es_luhn_valido, shannon_entropy
from monitor import procesar
from sanitizer import sanitizar

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GH_PAT = "github_pat_" + "11AAABBBCCC01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab"
OPENAI_PROJ = "sk-proj-" + "1234567890abcdefghijklmnopqrstuv"
SLACK_BOT = "xoxb-" + "123456789012-" + "1234567890123-" + "abcdefghijklmnopqrstuvwx"
STRIPE_KEY = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUv"
HF_TOKEN = "hf_" + "abcdefghijklmnopqrstuvwxyz12345678"


def test_entropia_baja_y_alta():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("password") < shannon_entropy("x9Kq2LmZ7wRt")


def test_regex_tipos_clasicos_y_modernos():
    assert detectar(f"key={AWS}")[0].tipo == "Clave AWS"
    assert detectar(GH)[0].tipo == "Token GitHub"
    assert detectar(GH_PAT)[0].tipo == "Token GitHub Fine-Grained"
    assert detectar(OPENAI_PROJ)[0].tipo == "Clave OpenAI"
    assert detectar(SLACK_BOT)[0].tipo == "Token Slack"
    assert detectar(STRIPE_KEY)[0].tipo == "Clave Stripe"
    assert detectar(HF_TOKEN)[0].tipo == "Token HuggingFace"
    assert detectar('DB="postgres://admin:Pa55w0rd@db.local/app"')[0].tipo == "Cadena de conexion"
    assert detectar("password = hunter2")[0].tipo == "Contrasena"
    assert detectar("Authorization: Bearer mySecretToken1234567890abcdef")[0].tipo == "Token Bearer"


def test_algoritmo_luhn_tarjetas():
    # Número de prueba con checksum Luhn válido (Visa dummy de test estándar)
    tarjeta_valida = "4012888888881881"
    tarjeta_invalida = "4012888888881882"
    assert es_luhn_valido(tarjeta_valida) is True
    assert es_luhn_valido(tarjeta_invalida) is False

    assert any(h.tipo == "Tarjeta de credito" for h in detectar(f"Pago: {tarjeta_valida}"))
    assert not any(h.tipo == "Tarjeta de credito" for h in detectar(f"Falso: {tarjeta_invalida}"))


def test_sanitizado_estrategias():
    t = f"key={AWS}\nprint('ok')"

    # 1. Asteriscos (conserva longitud)
    r_ast = sanitizar(t, detectar(t), estrategia="asteriscos")
    assert AWS not in r_ast and len(r_ast) == len(t)

    # 2. Parcial (muestra prefijo AKIA)
    r_parc = sanitizar(t, detectar(t), estrategia="parcial")
    assert "AKIA" in r_parc and "MNOP" in r_parc and "*" in r_parc

    # 3. Etiqueta
    r_eti = sanitizar(t, detectar(t), estrategia="etiqueta")
    assert "[PROTEGIDO: Clave AWS]" in r_eti


def test_texto_normal_sin_hallazgos():
    assert detectar("def suma(a, b):\n    return a + b  # suma dos numeros") == []


def test_filtro_uuids_y_git_commits():
    uuid_str = "123e4567-e89b-12d3-a456-426614174000"
    assert detectar(f"El id de usuario es {uuid_str}") == []

    git_commit_text = "commit 0123456789abcdef0123456789abcdef01234567 se introdujo ayer"
    assert detectar(git_commit_text) == []


def test_idempotente():
    t = f"token {GH} fin"
    r = sanitizar(t, detectar(t))
    assert detectar(r) == []


def test_solapamiento_se_une():
    t = "password=" + "Zq8" + "xK2mP9vL4nR7tY1wB5cD3fG6hJ0"
    assert len(detectar(t)) == 1


def test_database_avanzada(tmp_path):
    db = str(tmp_path / "test_adv.db")
    database.iniciar(db)

    # Registrar incidentes
    database.registrar("Clave AWS", "regex", 20, "sanitizado", "portapapeles", "Critica", db)
    database.registrar("Token GitHub", "regex", 40, "sanitizado", "portapapeles", "Critica", db)

    stats = database.estadisticas(db)
    assert stats["total"] == 2
    assert stats["hoy"] == 2
    assert "Clave AWS" in stats["por_tipo"]

    # Historial y filtrado
    hist = database.historial(limite=10, ruta=db)
    assert len(hist) == 2

    hist_filtrado = database.historial(tipo="Clave AWS", ruta=db)
    assert len(hist_filtrado) == 1

    # Exportación CSV
    csv_data = database.exportar_csv(db)
    assert "Clave AWS" in csv_data and "Token GitHub" in csv_data

    # Limpieza
    database.vaciar_historial(db)
    assert database.estadisticas(db)["total"] == 0


def test_monitor_registra_sin_secreto(tmp_path):
    db = str(tmp_path / "t.db")
    database.iniciar(db)
    nuevo, h = procesar(f"x {AWS}", "sanitizar", db)
    assert h and AWS not in nuevo
    fila = database.historial(ruta=db)[0]
    assert AWS not in str(fila) and fila["longitud"] == 20


def test_modo_alerta_no_modifica(tmp_path):
    db = str(tmp_path / "t.db")
    database.iniciar(db)
    t = f"x {AWS}"
    nuevo, h = procesar(t, "alerta", db)
    assert nuevo == t and h


def test_clipboard_modo_virtual():
    clipboard.activar_modo_virtual(True)
    assert clipboard.establecer_texto("secreto_memoria_123") is True
    assert clipboard.obtener_texto() == "secreto_memoria_123"
    clipboard.activar_modo_virtual(False)


def test_dashboard_api(tmp_path):
    import dashboard.main as d_main

    db_test = str(tmp_path / "dashboard_test.db")
    d_main.DB = db_test
    database.iniciar(db_test)

    # 1. Probar HTML
    html = d_main.inicio()
    assert "ShadowGuard" in html

    # 2. Probar Playground
    req_test = d_main.PruebaTextoRequest(texto=f"mi clave es {AWS}", estrategia="asteriscos")
    res_test = d_main.probar_texto(req_test)
    assert res_test["total_detectados"] == 1
    assert AWS not in res_test["texto_sanitizado"]

    # 3. Probar Configuración
    cfg = d_main.obtener_configuracion()
    assert "modo" in cfg

    req_cfg = d_main.ActualizarConfigRequest(modo="alerta")
    res_cfg = d_main.actualizar_configuracion(req_cfg)
    assert res_cfg["config"]["modo"] == "alerta"

    # 4. Probar Exportación CSV
    res_csv = d_main.exportar_csv()
    assert "text/csv" in res_csv.media_type

