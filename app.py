#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 API REST - NÚCLEO CENTRAL DE LA PLATAFORMA DE AUDITORÍA DE CIBERSEGURIDAD
==============================================================================

Descripción:
    Servidor Flask que actúa como comunicador central entre:
        - La capa de recolección de datos (network_scanner.py), que envía
          escaneos periódicos vía POST /api/actualizar_escaneo.
        - La capa de presentación (Dashboard web y vistas móviles por QR),
          que consulta el estado procesado vía GET /api/estado_red y
          GET /api/dispositivo/<ip>.

    Al iniciar, la aplicación carga una base de datos local de referencia
    (puertos_ciberseguridad.json) en un diccionario indexado por número de
    puerto, permitiendo búsquedas O(1) al enriquecer cada escaneo entrante
    con nivel de riesgo, servicio y descripción.

Dependencias:
    pip install flask flask-cors

Uso:
    python3 app.py

Nota sobre escalabilidad:
    El estado de la red se mantiene en una variable en memoria protegida
    por un lock. Esto es adecuado para una demostración/PoC ejecutada con
    un único proceso worker (p. ej. `flask run` o `app.run()`). Si en el
    futuro se despliega con múltiples workers (gunicorn -w N), el estado
    en memoria NO se compartirá entre procesos; en ese caso se debería
    migrar a un almacén externo (Redis, base de datos, etc.).
==============================================================================
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict

from flask import Flask, jsonify, request, Response
from flask_cors import CORS


# ==============================================================================
# 1. CONFIGURACIÓN GLOBAL
# ==============================================================================

# Ruta del archivo de base de datos local de puertos y riesgos.
RUTA_JSON_PUERTOS: str = "puertos_ciberseguridad.json"

# Host y puerto en los que escuchará el servidor Flask.
HOST_API: str = "0.0.0.0"
PUERTO_API: int = 5000
MODO_DEBUG: bool = True

# Niveles de riesgo reconocidos y su prioridad numérica para calcular el
# riesgo global de un dispositivo (a mayor número, mayor severidad).
PRIORIDAD_RIESGO: Dict[str, int] = {
    "critico": 4,
    "alto": 3,
    "medio": 2,
    "bajo": 1,
    "desconocido": 1,  # Se trata con la misma severidad base que "bajo".
}

# Metadatos de presentación (color/etiqueta) asociados a cada nivel de
# riesgo global calculado para un dispositivo.
ETIQUETAS_RIESGO_GLOBAL: Dict[str, Dict[str, str]] = {
    "critico": {"nivel": "CRITICO", "color": "ROJO"},
    "alto": {"nivel": "ALTO", "color": "NARANJA"},
    "medio": {"nivel": "MEDIO", "color": "AMARILLO"},
    "bajo": {"nivel": "BAJO", "color": "VERDE"},
}

# Valores por defecto para puertos que no están documentados en la base local.
RIESGO_PUERTO_DESCONOCIDO: str = "desconocido"
SERVICIO_PUERTO_DESCONOCIDO: str = "Desconocido"
DESCRIPCION_PUERTO_DESCONOCIDO: str = (
    "Puerto no documentado en la base de datos de referencia. "
    "Se recomienda investigar manualmente el servicio asociado."
)

# Configuración de logging.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("api_ciberseguridad")


# ==============================================================================
# 2. TIPOS AUXILIARES (Type Hints estructurados)
# ==============================================================================

class PuertoInfo(TypedDict, total=False):
    """Información de referencia de un puerto, tal como vive en el JSON local."""
    puerto: int
    protocolo: str
    servicio: str
    nivel_riesgo: str
    descripcion: str
    mitigacion: str


class PuertoEnriquecido(TypedDict, total=False):
    """Puerto abierto de un dispositivo, ya enriquecido con datos de riesgo."""
    puerto: int
    servicio: str
    nivel_riesgo: str
    descripcion: str
    mitigacion: Optional[str]


class DispositivoEnriquecido(TypedDict, total=False):
    """Dispositivo de red con sus puertos ya enriquecidos y riesgo global."""
    ip: str
    mac: str
    estado: str
    puertos_abiertos: List[PuertoEnriquecido]
    riesgo_global: Dict[str, str]


# ==============================================================================
# 3. CARGA DE LA BASE DE DATOS LOCAL DE PUERTOS (HASH MAP O(1))
# ==============================================================================

def cargar_base_de_datos_puertos(ruta_archivo: str) -> Dict[int, PuertoInfo]:
    """
    Carga el archivo JSON de referencia de puertos y lo aplana en un
    diccionario indexado por número de puerto, para permitir búsquedas
    en tiempo O(1) durante el enriquecimiento de cada escaneo.

    Args:
        ruta_archivo: Ruta al archivo puertos_ciberseguridad.json.

    Returns:
        Diccionario {numero_de_puerto: PuertoInfo}.

    Raises:
        SystemExit: Si el archivo no existe o su contenido es inválido,
            ya que la API no puede operar de forma confiable sin esta
            base de datos de referencia.
    """
    ruta = Path(ruta_archivo)

    if not ruta.is_file():
        logger.critical(
            f"No se encontró el archivo de base de datos '{ruta_archivo}'. "
            f"La API no puede iniciar sin esta referencia de puertos."
        )
        sys.exit(1)

    try:
        with ruta.open("r", encoding="utf-8") as f:
            contenido = json.load(f)
    except json.JSONDecodeError as e:
        logger.critical(f"El archivo '{ruta_archivo}' contiene JSON inválido: {e}")
        sys.exit(1)
    except OSError as e:
        logger.critical(f"No se pudo leer el archivo '{ruta_archivo}': {e}")
        sys.exit(1)

    mapa_puertos: Dict[int, PuertoInfo] = {}
    categorias = contenido.get("categorias", [])

    if not isinstance(categorias, list):
        logger.critical(
            "Formato inválido: se esperaba la clave 'categorias' como lista."
        )
        sys.exit(1)

    for categoria in categorias:
        nombre_categoria = categoria.get("categoria", "Sin categoría")
        lista_puertos = categoria.get("puertos", [])

        for entrada in lista_puertos:
            try:
                numero_puerto = int(entrada["puerto"])
            except (KeyError, TypeError, ValueError):
                logger.warning(
                    f"Entrada de puerto inválida u omitida en la categoría "
                    f"'{nombre_categoria}': {entrada}"
                )
                continue

            if numero_puerto in mapa_puertos:
                logger.warning(
                    f"Puerto duplicado detectado ({numero_puerto}) en la "
                    f"categoría '{nombre_categoria}'. Se conserva la primera "
                    f"definición encontrada."
                )
                continue

            mapa_puertos[numero_puerto] = {
                "puerto": numero_puerto,
                "protocolo": entrada.get("protocolo", "N/A"),
                "servicio": entrada.get("servicio", SERVICIO_PUERTO_DESCONOCIDO),
                "nivel_riesgo": entrada.get("nivel_riesgo", RIESGO_PUERTO_DESCONOCIDO),
                "descripcion": entrada.get("descripcion", ""),
                "mitigacion": entrada.get("mitigacion", ""),
            }

    logger.info(
        f"Base de datos de puertos cargada correctamente: "
        f"{len(mapa_puertos)} puertos indexados en memoria."
    )
    return mapa_puertos


# ==============================================================================
# 4. ESTADO GLOBAL EN MEMORIA
# ==============================================================================

# Diccionario {numero_de_puerto: PuertoInfo}, cargado una única vez al inicio.
BASE_DATOS_PUERTOS: Dict[int, PuertoInfo] = cargar_base_de_datos_puertos(
    RUTA_JSON_PUERTOS
)

# Último estado de red conocido, sobreescrito en cada POST /api/actualizar_escaneo.
# Se inicializa vacío para que GET /api/estado_red responda de forma consistente
# incluso antes de que el escáner haya enviado su primer reporte.
estado_red_actual: Dict[str, Any] = {
    "timestamp": None,
    "red_escaneada": None,
    "total_hosts_activos": 0,
    "dispositivos": [],
    "ultima_actualizacion_servidor": None,
}

# Lock para proteger el acceso concurrente al estado global en memoria,
# ya que Flask puede atender múltiples requests en hilos simultáneos.
_lock_estado: threading.Lock = threading.Lock()


# ==============================================================================
# 5. MOTOR DE ENRIQUECIMIENTO Y CÁLCULO DE RIESGO
# ==============================================================================

def enriquecer_puerto(numero_puerto: int) -> PuertoEnriquecido:
    """
    Cruza un número de puerto contra la base de datos local (O(1)) y
    devuelve su información de riesgo enriquecida. Si el puerto no está
    documentado, se clasifica como "desconocido".

    Args:
        numero_puerto: Número de puerto detectado como abierto.

    Returns:
        Diccionario PuertoEnriquecido con puerto, servicio, nivel_riesgo,
        descripcion y mitigacion.
    """
    info_referencia = BASE_DATOS_PUERTOS.get(numero_puerto)

    if info_referencia is not None:
        return {
            "puerto": numero_puerto,
            "servicio": info_referencia.get("servicio", SERVICIO_PUERTO_DESCONOCIDO),
            "nivel_riesgo": info_referencia.get(
                "nivel_riesgo", RIESGO_PUERTO_DESCONOCIDO
            ),
            "descripcion": info_referencia.get("descripcion", ""),
            "mitigacion": info_referencia.get("mitigacion", ""),
        }

    # Puerto no documentado en la base de referencia.
    return {
        "puerto": numero_puerto,
        "servicio": SERVICIO_PUERTO_DESCONOCIDO,
        "nivel_riesgo": RIESGO_PUERTO_DESCONOCIDO,
        "descripcion": DESCRIPCION_PUERTO_DESCONOCIDO,
        "mitigacion": "",
    }


def calcular_riesgo_global(puertos_enriquecidos: List[PuertoEnriquecido]) -> Dict[str, str]:
    """
    Determina el riesgo global de un dispositivo a partir del puerto más
    severo detectado entre todos sus puertos abiertos.

    Args:
        puertos_enriquecidos: Lista de puertos ya enriquecidos con
            nivel_riesgo.

    Returns:
        Diccionario con las claves 'nivel' (ej. "CRITICO") y 'color'
        (ej. "ROJO"), listo para ser consumido directamente por el frontend.
    """
    if not puertos_enriquecidos:
        # Sin puertos abiertos detectados: no hay superficie de ataque visible.
        return ETIQUETAS_RIESGO_GLOBAL["bajo"]

    nivel_mas_severo = max(
        puertos_enriquecidos,
        key=lambda p: PRIORIDAD_RIESGO.get(p["nivel_riesgo"], 0),
    )["nivel_riesgo"]

    # "desconocido" se presenta visualmente igual que "bajo" (mismo peso),
    # pero mantenemos la etiqueta de riesgo global dentro de las 4 categorías
    # estándar del dashboard.
    if nivel_mas_severo not in ETIQUETAS_RIESGO_GLOBAL:
        nivel_mas_severo = "bajo"

    return ETIQUETAS_RIESGO_GLOBAL[nivel_mas_severo]


def enriquecer_dispositivo(dispositivo_bruto: Dict[str, Any]) -> DispositivoEnriquecido:
    """
    Transforma un dispositivo recibido del escáner (con 'puertos_abiertos'
    como lista de enteros) en un dispositivo enriquecido con detalles de
    riesgo por puerto y un riesgo global calculado.

    Args:
        dispositivo_bruto: Diccionario tal como llega en el payload del
            POST, con al menos las claves ip, mac, estado y
            puertos_abiertos.

    Returns:
        DispositivoEnriquecido listo para almacenarse en el estado global.
    """
    puertos_abiertos_raw = dispositivo_bruto.get("puertos_abiertos", []) or []

    puertos_enriquecidos: List[PuertoEnriquecido] = []
    for numero_puerto in puertos_abiertos_raw:
        try:
            puertos_enriquecidos.append(enriquecer_puerto(int(numero_puerto)))
        except (TypeError, ValueError):
            logger.warning(
                f"Puerto no numérico ignorado en dispositivo "
                f"{dispositivo_bruto.get('ip', '?')}: {numero_puerto}"
            )

    return {
        "ip": dispositivo_bruto.get("ip", "N/A"),
        "mac": dispositivo_bruto.get("mac", "No detectada"),
        "estado": dispositivo_bruto.get("estado", "down"),
        "puertos_abiertos": puertos_enriquecidos,
        "riesgo_global": calcular_riesgo_global(puertos_enriquecidos),
    }


# ==============================================================================
# 6. VALIDACIÓN DEL PAYLOAD DE ENTRADA
# ==============================================================================

def validar_payload_escaneo(payload: Any) -> Optional[str]:
    """
    Valida de forma defensiva la estructura mínima esperada del payload
    enviado por el escáner.

    Args:
        payload: Cuerpo JSON deserializado de la petición.

    Returns:
        None si el payload es válido, o un string describiendo el primer
        error encontrado en caso contrario.
    """
    if not isinstance(payload, dict):
        return "El cuerpo de la petición debe ser un objeto JSON."

    if "dispositivos" not in payload:
        return "Falta la clave obligatoria 'dispositivos'."

    dispositivos = payload["dispositivos"]
    if not isinstance(dispositivos, list):
        return "'dispositivos' debe ser una lista."

    for indice, dispositivo in enumerate(dispositivos):
        if not isinstance(dispositivo, dict):
            return f"El dispositivo en la posición {indice} no es un objeto válido."
        if "ip" not in dispositivo or not dispositivo["ip"]:
            return f"El dispositivo en la posición {indice} no tiene 'ip'."
        if "puertos_abiertos" in dispositivo and not isinstance(
            dispositivo["puertos_abiertos"], list
        ):
            return (
                f"'puertos_abiertos' del dispositivo {dispositivo.get('ip')} "
                f"debe ser una lista."
            )

    return None


# ==============================================================================
# 7. INICIALIZACIÓN DE LA APLICACIÓN FLASK
# ==============================================================================

app = Flask(__name__)

# CORS habilitado para todas las rutas /api/*, ya que el dashboard y las
# vistas móviles se sirven desde un origen distinto al de esta API.
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ==============================================================================
# 8. ENDPOINT DE INGESTA (RECIBE DEL ESCÁNER)
# ==============================================================================

@app.route("/api/actualizar_escaneo", methods=["POST"])
def actualizar_escaneo() -> Response:
    """
    Recibe el resultado de un ciclo de escaneo desde network_scanner.py,
    enriquece cada dispositivo cruzando sus puertos abiertos contra la
    base de datos local, calcula el riesgo global por dispositivo y
    sobreescribe el estado de red en memoria.

    Returns:
        200 OK con un resumen de la ingesta si todo fue correcto.
        400 Bad Request si el payload está malformado o no es JSON válido.
        500 Internal Server Error ante cualquier fallo inesperado.
    """
    try:
        payload = request.get_json(force=False, silent=True)
    except Exception as e:
        logger.error(f"Error al parsear el JSON de la petición: {e}")
        payload = None

    if payload is None:
        return (
            jsonify(
                {
                    "error": "Cuerpo de la petición ausente o no es JSON válido.",
                    "detalle": "Verifique el header 'Content-Type: application/json'.",
                }
            ),
            400,
        )

    error_validacion = validar_payload_escaneo(payload)
    if error_validacion is not None:
        logger.warning(f"Payload de escaneo rechazado: {error_validacion}")
        return jsonify({"error": "Payload malformado.", "detalle": error_validacion}), 400

    try:
        dispositivos_enriquecidos = [
            enriquecer_dispositivo(dispositivo)
            for dispositivo in payload.get("dispositivos", [])
        ]

        nuevo_estado = {
            "timestamp": payload.get("timestamp"),
            "red_escaneada": payload.get("red_escaneada"),
            "total_hosts_activos": payload.get(
                "total_hosts_activos", len(dispositivos_enriquecidos)
            ),
            "dispositivos": dispositivos_enriquecidos,
            "ultima_actualizacion_servidor": time.time(),
        }

        # Sección crítica: se reemplaza el estado global de forma atómica.
        with _lock_estado:
            global estado_red_actual
            estado_red_actual = nuevo_estado

        logger.info(
            f"Estado de red actualizado: {len(dispositivos_enriquecidos)} "
            f"dispositivo(s) procesado(s) para la red "
            f"'{nuevo_estado['red_escaneada']}'."
        )

        return (
            jsonify(
                {
                    "mensaje": "Escaneo recibido y procesado correctamente.",
                    "dispositivos_procesados": len(dispositivos_enriquecidos),
                }
            ),
            200,
        )

    except Exception as e:
        # Cualquier error inesperado durante el enriquecimiento no debe
        # tumbar el servidor; se registra y se responde 500 de forma
        # controlada para que el escáner pueda registrar el fallo y
        # continuar con su siguiente ciclo.
        logger.exception(f"Error inesperado procesando el escaneo: {e}")
        return (
            jsonify(
                {
                    "error": "Error interno al procesar el escaneo.",
                    "detalle": str(e),
                }
            ),
            500,
        )


# ==============================================================================
# 9. ENDPOINTS DE SALIDA (SIRVEN AL FRONTEND Y AL MÓDULO QR)
# ==============================================================================

@app.route("/api/estado_red", methods=["GET"])
def obtener_estado_red() -> Response:
    """
    Retorna el estado completo y más reciente de la red, tal como fue
    almacenado en el último POST /api/actualizar_escaneo. Pensado para
    ser consumido por el Dashboard web (gráficos, inventario, mapa de
    calor de riesgo, etc.).

    Returns:
        200 OK con el estado completo en memoria (puede venir vacío si
        aún no se ha recibido ningún escaneo).
    """
    with _lock_estado:
        # Se retorna una copia superficial para no exponer la referencia
        # interna mutable directamente al serializador.
        estado_actual = dict(estado_red_actual)

    return jsonify(estado_actual), 200


@app.route("/api/dispositivo/<string:ip>", methods=["GET"])
def obtener_dispositivo_por_ip(ip: str) -> Response:
    """
    Busca, dentro del estado de red actual, el dispositivo cuya IP
    coincida exactamente con la solicitada y retorna su "tarjeta de
    seguridad" enriquecida. Pensado para ser consumido desde el
    navegador móvil de un visitante que escanea un código QR físico
    asociado a un dispositivo concreto.

    Args:
        ip: Dirección IP del dispositivo, tomada de la URL.

    Returns:
        200 OK con la tarjeta de seguridad del dispositivo si se encuentra.
        404 Not Found con un error estructurado si la IP no existe en el
        estado actual.
    """
    with _lock_estado:
        dispositivos = estado_red_actual.get("dispositivos", [])
        dispositivo_encontrado = next(
            (d for d in dispositivos if d.get("ip") == ip), None
        )

    if dispositivo_encontrado is None:
        return (
            jsonify(
                {
                    "error": "Dispositivo no encontrado en el último escaneo.",
                    "ip_solicitada": ip,
                }
            ),
            404,
        )

    return jsonify(dispositivo_encontrado), 200


# ==============================================================================
# 10. ENDPOINT DE SALUD (BONUS - ÚTIL PARA MONITOREO Y PRUEBAS RÁPIDAS)
# ==============================================================================

@app.route("/api/salud", methods=["GET"])
def salud() -> Response:
    """
    Endpoint ligero de verificación de vida del servicio (health check),
    útil para pruebas rápidas de conectividad y para orquestadores.

    Returns:
        200 OK con metadatos básicos del estado del servidor.
    """
    with _lock_estado:
        tiene_datos = estado_red_actual.get("timestamp") is not None

    return (
        jsonify(
            {
                "estado": "activo",
                "puertos_en_base_de_datos": len(BASE_DATOS_PUERTOS),
                "tiene_datos_de_escaneo": tiene_datos,
            }
        ),
        200,
    )


# ==============================================================================
# 11. MANEJADORES DE ERRORES GLOBALES
# ==============================================================================

@app.errorhandler(404)
def manejar_404(error: Any) -> Response:
    """Estructura en JSON cualquier error 404 no capturado explícitamente
    (por ejemplo, rutas inexistentes distintas a /api/dispositivo/<ip>)."""
    return (
        jsonify(
            {
                "error": "Recurso no encontrado.",
                "detalle": "La ruta solicitada no existe en esta API.",
            }
        ),
        404,
    )


@app.errorhandler(405)
def manejar_405(error: Any) -> Response:
    """Estructura en JSON los errores de método HTTP no permitido."""
    return (
        jsonify(
            {
                "error": "Método no permitido.",
                "detalle": "Verifique el método HTTP utilizado (GET/POST) para esta ruta.",
            }
        ),
        405,
    )


@app.errorhandler(500)
def manejar_500(error: Any) -> Response:
    """Estructura en JSON cualquier error interno no capturado explícitamente."""
    logger.exception(f"Error interno no controlado: {error}")
    return (
        jsonify(
            {
                "error": "Error interno del servidor.",
                "detalle": "Ocurrió un problema inesperado al procesar la solicitud.",
            }
        ),
        500,
    )


# ==============================================================================
# 12. PUNTO DE ENTRADA
# ==============================================================================

if __name__ == "__main__":
    logger.info(
        f"Iniciando API de auditoría de ciberseguridad en "
        f"http://{HOST_API}:{PUERTO_API} ..."
    )
    app.run(host=HOST_API, port=PUERTO_API, debug=MODO_DEBUG)

