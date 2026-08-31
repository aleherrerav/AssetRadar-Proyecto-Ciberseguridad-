from flask import Flask, jsonify

from database import (
    crear_base_datos,
    guardar_escaneo,
    comparar_ultimos_escaneos,
    listar_dispositivos,
    obtener_dispositivo_por_token,
)
from scanner import escanear_dispositivo

app = Flask(__name__)

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
    })


if __name__ == "__main__":
    # host="0.0.0.0" permite que otros dispositivos en la misma red
    # (celulares escaneando el QR, la laptop del dashboard) se conecten
    # a este servidor, no solo la propia máquina.
    app.run(debug=True, host="0.0.0.0", port=5000)
