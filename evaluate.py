"""evaluate.py - Dataset sintetico y metricas (Tabla 9 del informe). Uso: python evaluate.py"""
import random
import string
import time

from detector import detectar

random.seed(42)
B62 = string.ascii_letters + string.digits
B64 = B62 + "+/"


def r(alfabeto, n):
    return "".join(random.choice(alfabeto) for _ in range(n))


def jwt():
    return f"eyJ{r(B62, 20)}.eyJ{r(B62, 30)}.{r(B62, 43)}"


N = 30
grupos = {
    "Claves y tokens (AWS, GitHub, OpenAI, Google)": (True, [
        random.choice([
            lambda: "AKIA" + r(string.ascii_uppercase + string.digits, 16),
            lambda: "ghp_" + r(B62, 36),
            lambda: "sk-" + r(B62, 40),
            lambda: "AIza" + r(B62 + "_-", 35)])()
        for _ in range(N)]),
    "JWT y claves PEM": (True, [
        jwt() if i % 2 else f"-----BEGIN RSA PRIVATE KEY-----\n{r(B64, 64)}\n{r(B64, 64)}\n-----END RSA PRIVATE KEY-----"
        for i in range(N)]),
    "Contrasenas y cadenas de conexion": (True, [
        f"password = '{r(B62, 10)}'" if i % 2 else f"postgres://user{i}:{r(B62, 9)}@db.local/app"
        for i in range(N)]),
    "Cadenas aleatorias (entropia)": (True, [
        f"token interno: {r(B64, 40)}" if i % 2 else f"clave: {r('0123456789abcdef', 40)}"
        for i in range(N)]),
    "Texto normal sin secretos": (False, [
        random.choice([
            "Hola, necesito ayuda para entender como funciona un bucle for en Python.",
            "def suma(a, b):\n    return a + b  # suma dos numeros",
            "SELECT nombre, correo FROM clientes WHERE activo = 1 ORDER BY nombre;",
            "import os\nruta = os.path.join('datos', 'archivo.csv')\nprint(ruta)",
            "La reunion del equipo es el lunes a las 10:00 en la sala de conferencias.",
            "class UsuarioRepositorioConfiguracionDeSistema:\n    pass",
            "git commit -m 'corrige error en el modulo de autenticacion de usuarios'",
            "El commit " + r("0123456789abcdef", 40) + " introdujo el cambio."])  # hash legitimo -> FP esperado
        for _ in range(N * 2)]),
}

VP = FN = FP = 0
tiempos = []
print(f"{'Grupo':48}{'N':>4}{'VP':>5}{'FN':>5}{'FP':>5}")
for nombre, (tiene, muestras) in grupos.items():
    vp = fn = fp = 0
    for m in muestras:
        t0 = time.perf_counter()
        hall = detectar(m)
        tiempos.append((time.perf_counter() - t0) * 1000)
        if tiene:
            vp, fn = (vp + 1, fn) if hall else (vp, fn + 1)
        elif hall:
            fp += 1
    VP, FN, FP = VP + vp, FN + fn, FP + fp
    print(f"{nombre:48}{len(muestras):>4}{(vp if tiene else '-'):>5}{(fn if tiene else '-'):>5}{fp:>5}")

print(f"\nPrecision = {100 * VP / (VP + FP):.1f} %  (VP/(VP+FP))")
print(f"Tasa de deteccion = {100 * VP / (VP + FN):.1f} %  (VP/(VP+FN))")
print(f"Tiempo medio = {sum(tiempos) / len(tiempos):.3f} ms por texto")
