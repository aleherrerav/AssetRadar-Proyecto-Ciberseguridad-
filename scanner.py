#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 MÓDULO DE ESCANEO - Sistema de Descubrimiento de Activos con Módulo QR
 UNICTEC 2026
==============================================================================

Descripción:
    Escanea un dispositivo individual (por IP) usando 'python-nmap', enriquece
    cada puerto encontrado con la información del catálogo de riesgos
    investigado por el Equipo de Implementación (catalogo_puertos.json), y
    devuelve el resultado listo para guardarse en la base de datos o
    mostrarse en la tarjeta de seguridad del QR.

    Este módulo se llama BAJO DEMANDA desde el backend (app.py) cada vez que:
      - Se escanea un dispositivo señuelo desde el dashboard.
      - Alguien escanea el QR físico de un dispositivo.
    No corre en segundo plano ni escanea subredes completas, para mantener
    los tiempos de respuesta rápidos en la demo.

Requisitos:
    - Nmap instalado y accesible en el PATH del sistema operativo.
    - En Windows: Npcap instalado (idealmente en modo compatible con WinPcap).
    - Privilegios de administrador/root para usar -sS (SYN scan).
      Si no se ejecuta con privilegios elevados, cae automáticamente a -sT
      (TCP connect scan), que funciona sin permisos especiales.
    - Dependencias Python: pip install python-nmap

Advertencia legal:
    Ejecutar este script únicamente contra dispositivos propios del equipo
    o sobre la red aislada creada para la feria. Nunca contra redes o
    dispositivos de terceros sin autorización explícita.
==============================================================================
"""

import os
import json
import logging

import nmap  # python-nmap

# ==============================================================================
# 1. CONFIGURACIÓN
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("scanner")

# Puertos que se escanean EN VIVO durante la demo: subconjunto curado del
# catálogo completo (130+ puertos), enfocado en los dispositivos señuelo
# (cámara IP, router, impresora). Escanear todo el catálogo sería demasiado
# lento para una demo en vivo.
PUERTOS_A_ESCANEAR = "21,22,23,53,80,443,445,515,554,631,1883,1900,3389,5900,8080,8291,8554,8883,9100,9101,37777"

# Nivel de tiempo de Nmap (0=paranoico ... 5=insano). T4 = rápido y estable,
# apropiado para una red local pequeña y controlada.
TIMING_TEMPLATE = "-T4"

RUTA_CATALOGO = os.path.join(os.path.dirname(__file__), "catalogo_puertos.json")


# ==============================================================================
# 2. CARGA DEL CATÁLOGO DE RIESGOS
# ==============================================================================

def cargar_catalogo_puertos(ruta=RUTA_CATALOGO):
    """
    Carga catalogo_puertos.json y lo convierte en un diccionario indexado
    por número de puerto, para consulta rápida: catalogo[23] -> info Telnet.
    """
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            categorias = json.load(f)
    except FileNotFoundError:
        logger.warning(
            f"No se encontró {ruta}. Los resultados no tendrán nivel de "
            f"riesgo/descripción/mitigación enriquecidos."
        )
        return {}

    catalogo = {}
    for categoria in categorias:
        for p in categoria.get("puertos", []):
            catalogo[p["puerto"]] = p
    return catalogo


CATALOGO_PUERTOS = cargar_catalogo_puertos()


# ==============================================================================
# 3. DETECCIÓN DE PRIVILEGIOS (idea rescatada del script del compañero)
# ==============================================================================

def tiene_privilegios_admin() -> bool:
    """
    Determina si el script corre con privilegios elevados.
    -sS (SYN scan) requiere privilegios de root/administrador. Sin ellos,
    se debe usar -sT (TCP connect scan), que no necesita permisos especiales
    pero es un poco más lento.
    """
    try:
        return os.geteuid() == 0  # Linux/Mac
    except AttributeError:
        # Windows no tiene geteuid(); se intenta detectar con ctypes.
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def construir_flags_tcp() -> str:
    """
    Elige -sS (más rápido, requiere admin) o -sT (sin privilegios) según
    corresponda, y arma los argumentos de Nmap para el escaneo curado.
    """
    tecnica = "-sS" if tiene_privilegios_admin() else "-sT"
    return f"{tecnica} {TIMING_TEMPLATE}"


# ==============================================================================
# 4. ESCANEO DE UN DISPOSITIVO (bajo demanda)
# ==============================================================================

def escanear_dispositivo(ip: str) -> list:
    """
    Escanea un único dispositivo sobre el conjunto curado de puertos y
    devuelve una lista de diccionarios enriquecidos con el catálogo.

    Args:
        ip: Dirección IP del dispositivo a escanear.

    Returns:
        Lista de dicts: puerto, servicio, estado, nivel_riesgo,
        descripcion, mitigacion.
    """
    resultados = []
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=ip, ports=PUERTOS_A_ESCANEAR, arguments=construir_flags_tcp())
    except nmap.PortScannerError as e:
        logger.error(f"Error de Nmap escaneando {ip}: {e}")
        return resultados
    except Exception as e:
        logger.error(f"Error inesperado escaneando {ip}: {e}")
        return resultados

    if ip not in scanner.all_hosts():
        logger.info(f"{ip} no respondió al escaneo (host caído o fuera de la red).")
        return resultados

    host_info = scanner[ip]
    if "tcp" not in host_info:
        return resultados

    for puerto, datos_puerto in host_info["tcp"].items():
        info_catalogo = CATALOGO_PUERTOS.get(puerto, {})
        resultados.append({
            "puerto": puerto,
            "servicio": datos_puerto.get("name", info_catalogo.get("servicio", "desconocido")),
            "estado": datos_puerto.get("state", "desconocido"),  # open / closed / filtered
            "nivel_riesgo": info_catalogo.get("nivel_riesgo", "no clasificado"),
            "descripcion": info_catalogo.get("descripcion", ""),
            "mitigacion": info_catalogo.get("mitigacion", ""),
        })

    resultados.sort(key=lambda r: r["puerto"])
    return resultados


# ==============================================================================
# 5. UTILIDAD: escanear varios dispositivos conocidos de una sola vez
#    (por ejemplo, para un botón "Actualizar todo" en el dashboard).
#    Se hace de forma SECUENCIAL a propósito: con solo 3-4 dispositivos
#    señuelo no hace falta paralelizar, y así se evita la complejidad y los
#    problemas de compatibilidad de multiprocessing en Windows.
# ==============================================================================

def escanear_varios(lista_ips: list) -> dict:
    """
    Escanea una lista de IPs conocidas, una por una, y devuelve un
    diccionario {ip: resultados}.
    """
    resultados_totales = {}
    for ip in lista_ips:
        logger.info(f"Escaneando {ip}...")
        resultados_totales[ip] = escanear_dispositivo(ip)
    return resultados_totales


# ==============================================================================
# PRUEBA MANUAL DEL MÓDULO
# ==============================================================================

if __name__ == "__main__":
    if not tiene_privilegios_admin():
        logger.warning(
            "No se detectaron privilegios de administrador/root. "
            "Se usará -sT (TCP connect scan) en lugar de -sS. "
            "Funciona igual, solo es un poco más lento."
        )

    ip_prueba = "127.0.0.1"  # Cambiar por la IP real de un dispositivo señuelo
    print(f"Escaneando {ip_prueba}...\n")
    resultado = escanear_dispositivo(ip_prueba)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))
