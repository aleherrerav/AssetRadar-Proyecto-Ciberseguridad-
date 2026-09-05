#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 SCANNER DE RED CONCURRENTE - CAPA DE RECOLECCIÓN PARA AUDITORÍA EN TIEMPO REAL
==============================================================================

Descripción:
    Este script realiza escaneos de red continuos sobre una subred objetivo,
    utilizando 'python-nmap' como wrapper de Nmap y 'concurrent.futures.
    ProcessPoolExecutor' para paralelizar el trabajo entre múltiples núcleos
    de CPU. Cada proceso hijo escanea un host individual (TCP + UDP) y el
    proceso principal consolida los resultados en una lista de diccionarios
    que se envía por HTTP POST a un backend (por ejemplo, Flask).

Requisitos del sistema:
    - Nmap instalado y accesible en el PATH del sistema operativo.
    - Privilegios de root/administrador para usar -sS (SYN scan) y -sU (UDP).
      Si no se ejecuta como root, el script cae automáticamente a -sT.
    - Dependencias Python:  pip install python-nmap requests

Uso:
    sudo python3 network_scanner.py

Advertencia legal:
    Ejecute este script únicamente contra redes/hosts sobre los que tenga
    autorización explícita para realizar pruebas. El escaneo de puertos no
    autorizado puede ser ilegal en su jurisdicción.
==============================================================================
"""

import os
import sys
import time
import json
import logging
import ipaddress
from concurrent.futures import ProcessPoolExecutor, as_completed

import requests
import nmap  # python-nmap


# ==============================================================================
# 1. VARIABLES GLOBALES DE CONFIGURACIÓN
# ==============================================================================

# Red objetivo en notación CIDR. Ajustar según el entorno de auditoría.
RED_OBJETIVO = "192.168.1.0/24"

# Endpoint del backend (Flask) que recibirá los resultados consolidados.
API_URL = "http://127.0.0.1:5000/api/actualizar_escaneo"

# Número de procesos paralelos. El enunciado indica un equipo de 16 núcleos;
# se deja 1 núcleo libre para el SO y el proceso orquestador principal.
MAX_WORKERS = 15

# Segundos de espera entre cada ciclo completo de escaneo de la subred.
INTERVALO_CICLOS_SEGUNDOS = 60

# Modo de prueba de concepto local: si es True, los resultados se imprimen
# de forma legible en la terminal y NO se envían a la API (útil cuando el
# backend Flask aún no está desplegado). Si es False, se ejecuta el flujo
# normal de producción enviando los datos vía POST a API_URL.
MODO_DEMO_LOCAL = True

# Timeout (segundos) para la petición HTTP POST hacia el backend.
API_TIMEOUT_SEGUNDOS = 10

# Puertos UDP considerados críticos para el escaneo (DNS, DHCP, NTP, SNMP...).
PUERTOS_UDP_CRITICOS = "53,67,68,123,161,500"

# Rango de puertos TCP a escanear. "-p-" = los 65535 puertos completos.
# Se puede sustituir por "--top-ports 10000" si se requiere un balance
# distinto entre exhaustividad y velocidad.
RANGO_PUERTOS_TCP = "-p-"

# Timeout máximo por host individual, evita que un host "colgado"
# bloquee indefinidamente un proceso worker.
HOST_TIMEOUT = "5m"

# Tasa mínima de paquetes por segundo (velocidad agresiva pero estable).
MIN_RATE = "1000"

# Número máximo de reintentos por puerto antes de descartarlo.
MAX_RETRIES = "2"

# Nivel de tiempo de Nmap (0=paranoico ... 5=insano). T4 = agresivo/estable.
TIMING_TEMPLATE = "-T4"

# Configuración del logging a consola.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("network_scanner")


# ==============================================================================
# 2. UTILIDADES DE CONFIGURACIÓN DE PRIVILEGIOS
# ==============================================================================

def tiene_privilegios_root() -> bool:
    """
    Determina si el script se está ejecutando con privilegios elevados.
    -sS (SYN scan) y -sU (UDP scan) de Nmap requieren privilegios de root
    en sistemas Unix/Linux. Si no se cuenta con ellos, se debe usar -sT
    (TCP connect scan) para evitar errores de Nmap.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # os.geteuid() no existe en Windows; se asume falta de privilegios
        # especiales y se recomienda ejecutar como Administrador.
        return False


def construir_flags_tcp() -> str:
    """
    Construye la cadena de argumentos Nmap para el escaneo TCP,
    seleccionando -sS (SYN, requiere root) o -sT (connect, sin privilegios)
    según los privilegios disponibles, además de las flags de rendimiento.
    """
    tecnica = "-sS" if tiene_privilegios_root() else "-sT"
    return (
        f"{tecnica} {RANGO_PUERTOS_TCP} {TIMING_TEMPLATE} "
        f"--min-rate {MIN_RATE} --max-retries {MAX_RETRIES} "
        f"--host-timeout {HOST_TIMEOUT} -n"
    )


def construir_flags_udp() -> str:
    """
    Construye la cadena de argumentos Nmap para el escaneo UDP de los
    puertos críticos definidos en PUERTOS_UDP_CRITICOS.
    """
    return (
        f"-sU -p {PUERTOS_UDP_CRITICOS} {TIMING_TEMPLATE} "
        f"--min-rate {MIN_RATE} --max-retries {MAX_RETRIES} "
        f"--host-timeout {HOST_TIMEOUT} -n"
    )


# ==============================================================================
# 3. LÓGICA DE ESCANEO POR HOST (Ejecutada en cada proceso worker)
# ==============================================================================

def escanear_host(ip: str) -> dict:
    """
    Escanea un único host (TCP completo + UDP crítico) y devuelve un
    diccionario normalizado con la información relevante.

    Esta función se ejecuta dentro de un proceso independiente
    (ProcessPoolExecutor), por lo que debe instanciar su propio objeto
    nmap.PortScanner y no debe depender de estado compartido con el
    proceso principal.

    Args:
        ip: Dirección IP del host a escanear.

    Returns:
        dict con las claves: ip, mac, estado, puertos_abiertos.
    """
    resultado = {
        "ip": ip,
        "mac": "No detectada",
        "estado": "down",
        "puertos_abiertos": [],
    }

    scanner = nmap.PortScanner()

    # --- Escaneo TCP (rango completo / top ports) ---
    try:
        scanner.scan(hosts=ip, arguments=construir_flags_tcp())
        if ip in scanner.all_hosts():
            host_info = scanner[ip]
            resultado["estado"] = host_info.state()  # 'up' / 'down'

            # Dirección MAC (solo disponible normalmente en redes locales/L2).
            try:
                resultado["mac"] = host_info["addresses"].get("mac", "No detectada")
            except (KeyError, AttributeError):
                resultado["mac"] = "No detectada"

            # Extracción de puertos TCP estrictamente en estado 'open'.
            if "tcp" in host_info:
                for puerto, datos_puerto in host_info["tcp"].items():
                    if datos_puerto.get("state") == "open":
                        resultado["puertos_abiertos"].append(int(puerto))

    except nmap.PortScannerError as e:
        logger.error(f"[TCP] Error de Nmap escaneando {ip}: {e}")
    except Exception as e:
        logger.error(f"[TCP] Error inesperado escaneando {ip}: {e}")

    # --- Escaneo UDP (puertos críticos) ---
    # Se ejecuta incluso si el host no respondió al TCP, ya que algunos
    # hosts filtran ICMP/TCP pero responden a servicios UDP como DNS/NTP.
    try:
        scanner_udp = nmap.PortScanner()
        scanner_udp.scan(hosts=ip, arguments=construir_flags_udp())
        if ip in scanner_udp.all_hosts():
            host_info_udp = scanner_udp[ip]

            # Si el host no había sido marcado 'up' en el TCP, se actualiza.
            if resultado["estado"] != "up":
                resultado["estado"] = host_info_udp.state()

            if "udp" in host_info_udp:
                for puerto, datos_puerto in host_info_udp["udp"].items():
                    if datos_puerto.get("state") == "open":
                        resultado["puertos_abiertos"].append(int(puerto))

    except nmap.PortScannerError as e:
        logger.error(f"[UDP] Error de Nmap escaneando {ip}: {e}")
    except Exception as e:
        logger.error(f"[UDP] Error inesperado escaneando {ip}: {e}")

    # Se eliminan duplicados y se ordenan los puertos para un output limpio.
    resultado["puertos_abiertos"] = sorted(set(resultado["puertos_abiertos"]))

    return resultado


# ==============================================================================
# 4. ORQUESTACIÓN DEL ESCANEO PARALELO DE LA SUBRED
# ==============================================================================

def obtener_lista_de_hosts(red_cidr: str) -> list:
    """
    Expande la subred en notación CIDR a una lista de direcciones IP
    individuales (excluyendo red y broadcast cuando aplica).

    Args:
        red_cidr: Subred en formato CIDR, ej. "192.168.1.0/24".

    Returns:
        Lista de strings con cada IP host de la subred.
    """
    try:
        red = ipaddress.ip_network(red_cidr, strict=False)
        return [str(ip) for ip in red.hosts()]
    except ValueError as e:
        logger.critical(f"Red objetivo inválida '{red_cidr}': {e}")
        sys.exit(1)


def ejecutar_barrido_paralelo(lista_ips: list) -> list:
    """
    Distribuye el escaneo de cada IP entre múltiples procesos usando
    ProcessPoolExecutor, aprovechando los núcleos disponibles del CPU.

    Args:
        lista_ips: Lista de direcciones IP a escanear.

    Returns:
        Lista de diccionarios con los resultados de cada host escaneado.
        Solo se incluyen hosts que efectivamente respondieron o tuvieron
        datos relevantes (se descartan errores silenciosos de futuros).
    """
    resultados_consolidados = []

    logger.info(
        f"Iniciando barrido de {len(lista_ips)} hosts con {MAX_WORKERS} "
        f"procesos en paralelo..."
    )

    with ProcessPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Se mapea cada IP a un futuro (future) independiente.
        futuros_a_ip = {
            executor.submit(escanear_host, ip): ip for ip in lista_ips
        }

        for futuro in as_completed(futuros_a_ip):
            ip_objetivo = futuros_a_ip[futuro]
            try:
                datos_host = futuro.result()
                resultados_consolidados.append(datos_host)
                if datos_host["estado"] == "up":
                    logger.info(
                        f"Host activo: {datos_host['ip']} | "
                        f"MAC: {datos_host['mac']} | "
                        f"Puertos abiertos: {datos_host['puertos_abiertos']}"
                    )
            except Exception as e:
                # Un fallo en un proceso individual NO debe detener el resto
                # del barrido; se registra y se continúa.
                logger.error(f"Fallo escaneando el host {ip_objetivo}: {e}")

    return resultados_consolidados


# ==============================================================================
# 5. VISUALIZACIÓN LOCAL EN CONSOLA (MODO DEMO)
# ==============================================================================

def mostrar_resultados_consola(resultados: list) -> None:
    """
    Imprime en la terminal, de forma estructurada y legible, los datos de
    cada host escaneado (IP, MAC, Estado y Puertos Abiertos). Se utiliza
    en MODO_DEMO_LOCAL como sustituto del envío a la API, para poder
    validar el funcionamiento del motor de escaneo sin depender de un
    backend Flask desplegado.

    Args:
        resultados: Lista de diccionarios con los datos de cada host,
            en el formato {ip, mac, estado, puertos_abiertos}.
    """
    separador = "=" * 60
    print(f"\n{separador}")
    print(" RESULTADOS DEL ESCANEO - MODO DEMOSTRACIÓN LOCAL")
    print(f"{separador}")

    if not resultados:
        print("No se obtuvieron resultados en este ciclo de escaneo.\n")
        return

    hosts_activos = [r for r in resultados if r["estado"] == "up"]
    print(f"Total de hosts escaneados: {len(resultados)}")
    print(f"Total de hosts activos (up): {len(hosts_activos)}")
    print(f"{separador}\n")

    for host in resultados:
        # Solo se muestran en detalle los hosts activos para no saturar la
        # consola con decenas de hosts 'down' sin información relevante.
        if host["estado"] != "up":
            continue

        print(f"Dispositivo detectado:")
        print(f"\tIP:               {host['ip']}")
        print(f"\tMAC:              {host['mac']}")
        print(f"\tEstado:           {host['estado']}")

        if host["puertos_abiertos"]:
            print(f"\tPuertos Abiertos: {host['puertos_abiertos']}")
        else:
            print(f"\tPuertos Abiertos: Ninguno detectado")

        print(f"{'-' * 60}")

    # Adicionalmente, se muestra el bloque completo en formato JSON con
    # indentación, útil para copiar/pegar o validar la estructura exacta
    # que recibiría la API en un entorno de producción.
    print("\nRepresentación JSON completa del ciclo:")
    print(json.dumps(resultados, indent=4, ensure_ascii=False))
    print(f"{separador}\n")


# ==============================================================================
# 6. ENVÍO DE RESULTADOS AL BACKEND (API REST)
# ==============================================================================

def enviar_resultados_api(resultados: list) -> None:
    """
    Envía la lista consolidada de resultados al backend mediante una
    petición HTTP POST en formato JSON. Maneja de forma robusta los
    errores de red o de servidor para que el bucle principal nunca se
    detenga por una falla en la API.

    Args:
        resultados: Lista de diccionarios con los datos de cada host.
    """
    payload = {
        "timestamp": time.time(),
        "red_escaneada": RED_OBJETIVO,
        "total_hosts_activos": sum(1 for r in resultados if r["estado"] == "up"),
        "dispositivos": resultados,
    }

    try:
        respuesta = requests.post(
            API_URL,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=API_TIMEOUT_SEGUNDOS,
        )
        respuesta.raise_for_status()
        logger.info(
            f"Resultados enviados correctamente a la API "
            f"(status {respuesta.status_code})."
        )

    except requests.exceptions.ConnectionError:
        logger.error(
            f"No se pudo conectar con el backend en '{API_URL}'. "
            f"¿Está el servidor Flask activo? Se continuará en el "
            f"siguiente ciclo."
        )
    except requests.exceptions.Timeout:
        logger.error(
            f"Timeout ({API_TIMEOUT_SEGUNDOS}s) al intentar enviar los "
            f"resultados a la API. Se continuará en el siguiente ciclo."
        )
    except requests.exceptions.HTTPError as e:
        logger.error(f"El backend respondió con un error HTTP: {e}")
    except requests.exceptions.RequestException as e:
        # Captura genérica para cualquier otro error de la librería requests.
        logger.error(f"Error de red inesperado al contactar la API: {e}")
    except (TypeError, ValueError) as e:
        # Errores de serialización JSON, por si algún dato no es serializable.
        logger.error(f"Error al serializar el payload a JSON: {e}")


# ==============================================================================
# 7. BUCLE PRINCIPAL DE EJECUCIÓN CONTINUA
# ==============================================================================

def main() -> None:
    """
    Punto de entrada principal. Ejecuta ciclos infinitos de:
        1) Expansión de la subred objetivo en hosts individuales.
        2) Escaneo paralelo (TCP + UDP) de todos los hosts.
        3) Envío de resultados consolidados al backend vía API REST.
        4) Espera antes de iniciar el siguiente ciclo.
    """
    if not tiene_privilegios_root():
        logger.warning(
            "El script no se está ejecutando con privilegios de root/admin. "
            "Se usará -sT (TCP connect scan) en lugar de -sS (SYN scan), "
            "lo cual puede ser más lento y más fácil de detectar por IDS."
        )

    logger.info(f"Red objetivo configurada: {RED_OBJETIVO}")
    logger.info(f"Endpoint de la API: {API_URL}")
    logger.info(f"Workers configurados: {MAX_WORKERS}")
    if MODO_DEMO_LOCAL:
        logger.warning(
            "MODO_DEMO_LOCAL está activado: los resultados se imprimirán "
            "en consola y NO se enviarán a la API."
        )

    ciclo = 1
    while True:
        logger.info(f"===== INICIO DEL CICLO DE ESCANEO #{ciclo} =====")
        inicio = time.time()

        try:
            hosts_a_escanear = obtener_lista_de_hosts(RED_OBJETIVO)
            resultados = ejecutar_barrido_paralelo(hosts_a_escanear)

            # Bifurcación del flujo según el modo de ejecución configurado:
            # - MODO_DEMO_LOCAL = True  -> impresión local, sin llamadas de red.
            # - MODO_DEMO_LOCAL = False -> flujo normal de producción (API REST).
            if MODO_DEMO_LOCAL:
                mostrar_resultados_consola(resultados)
            else:
                enviar_resultados_api(resultados)

        except KeyboardInterrupt:
            logger.info("Interrupción manual detectada. Finalizando script.")
            sys.exit(0)
        except Exception as e:
            # Red de seguridad final: ningún error inesperado dentro de un
            # ciclo debe tumbar el proceso principal del scanner.
            logger.error(f"Error inesperado durante el ciclo #{ciclo}: {e}")

        duracion = time.time() - inicio
        logger.info(
            f"===== FIN DEL CICLO #{ciclo} (duración: {duracion:.2f}s) ====="
        )
        ciclo += 1

        logger.info(
            f"Esperando {INTERVALO_CICLOS_SEGUNDOS}s antes del próximo ciclo...\n"
        )
        time.sleep(INTERVALO_CICLOS_SEGUNDOS)


if __name__ == "__main__":
    main()
