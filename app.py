from flask import Flask, jsonify
from flask_cors import CORS

from database import (
    crear_base_datos,
    guardar_escaneo,
    comparar_ultimos_escaneos,
    listar_dispositivos,
    obtener_dispositivo_por_token,
)
from scanner import escanear_dispositivo

app = Flask(__name__)

# CORS habilitado para /api/*: necesario si el dashboard del equipo de
# Implementación corre en un servidor/puerto distinto a este backend
# (por ejemplo, si abren el HTML con Live Server en el puerto 5500).
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Prioridad numérica de cada nivel de riesgo, para calcular el riesgo
# GLOBAL de un dispositivo a partir de su puerto más peligroso.
PRIORIDAD_RIESGO = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "no clasificado": 1}

# Etiquetas de presentación listas para que el dashboard las pinte
# directamente (nivel + color), sin tener que traducir nada del lado del frontend.
ETIQUETAS_RIESGO_GLOBAL = {
    "critico": {"nivel": "CRITICO", "color": "ROJO"},
    "alto": {"nivel": "ALTO", "color": "NARANJA"},
    "medio": {"nivel": "MEDIO", "color": "AMARILLO"},
    "bajo": {"nivel": "BAJO", "color": "VERDE"},
}


def calcular_riesgo_global(puertos_enriquecidos):
    """
    Determina el riesgo global de un dispositivo a partir del puerto
    ABIERTO más severo entre todos los encontrados. Si no hay puertos
    abiertos, el dispositivo se considera de riesgo bajo (buena señal).
    """
    puertos_abiertos = [p for p in puertos_enriquecidos if p.get("estado") == "open"]

    if not puertos_abiertos:
        return ETIQUETAS_RIESGO_GLOBAL["bajo"]

    nivel_mas_severo = max(
        puertos_abiertos,
        key=lambda p: PRIORIDAD_RIESGO.get(p.get("nivel_riesgo", "no clasificado"), 0),
    )["nivel_riesgo"]

    if nivel_mas_severo not in ETIQUETAS_RIESGO_GLOBAL:
        nivel_mas_severo = "bajo"

    return ETIQUETAS_RIESGO_GLOBAL[nivel_mas_severo]


# Asegura que la base de datos y sus tablas existan al arrancar el servidor.
crear_base_datos()


@app.route("/api/dispositivos")
def api_listar_dispositivos():
    """
    Devuelve la lista de todos los dispositivos registrados.
    El dashboard (equipo de Implementación) consume este endpoint para
    construir la tabla principal.
    """
    return jsonify(listar_dispositivos())


@app.route("/api/escanear/<int:dispositivo_id>/<ip>")
def api_escanear(dispositivo_id, ip):
    """
    Escanea un dispositivo por su IP, guarda el resultado en la base de
    datos y devuelve tanto los puertos encontrados como los cambios
    respecto al escaneo anterior (si existe).

    Ejemplo de uso: GET /api/escanear/1/192.168.50.10
    """
    resultados = escanear_dispositivo(ip)
    guardar_escaneo(dispositivo_id, resultados)
    comparacion = comparar_ultimos_escaneos(dispositivo_id)

    return jsonify({
        "puertos": resultados,
        "cambios": comparacion["cambios"],
        "riesgo_global": calcular_riesgo_global(resultados),
    })


@app.route("/dispositivo/<token>")
def tarjeta_seguridad(token):
    """
    Endpoint al que apunta cada código QR físico. Cuando alguien lo
    escanea con su celular, este endpoint escanea el dispositivo en
    tiempo real y devuelve su "tarjeta de seguridad".
    """
    dispositivo = obtener_dispositivo_por_token(token)

    if dispositivo is None:
        return jsonify({"error": "Dispositivo no encontrado"}), 404

    resultados = escanear_dispositivo(dispositivo["ip"])
    guardar_escaneo(dispositivo["id"], resultados)

    return jsonify({
        "nombre": dispositivo["nombre"],
        "ip": dispositivo["ip"],
        "puertos": resultados,
        "riesgo_global": calcular_riesgo_global(resultados),
    })


@app.route("/api/salud")
def salud():
    """
    Endpoint ligero para confirmar rápidamente que el servidor está vivo
    y cuántos dispositivos hay registrados. Útil para pruebas rápidas el
    día de la feria sin tener que escanear nada.
    """
    return jsonify({
        "estado": "activo",
        "dispositivos_registrados": len(listar_dispositivos()),
    })


@app.errorhandler(404)
def manejar_404(error):
    return jsonify({"error": "Recurso no encontrado", "detalle": "La ruta solicitada no existe."}), 404


@app.errorhandler(500)
def manejar_500(error):
    return jsonify({"error": "Error interno del servidor", "detalle": "Ocurrió un problema inesperado."}), 500


if __name__ == "__main__":
    # host="0.0.0.0" permite que otros dispositivos en la misma red
    # (celulares escaneando el QR, la laptop del dashboard) se conecten
    # a este servidor, no solo la propia máquina.
    app.run(debug=True, host="0.0.0.0", port=5000)
