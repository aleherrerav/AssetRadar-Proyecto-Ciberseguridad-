import sqlite3
from datetime import datetime


def crear_base_datos():
    """
    Crea (si no existe) el archivo database.db con las tres tablas
    principales del proyecto:
      - dispositivos: cada dispositivo señuelo, con su token QR único.
      - escaneos: un registro por cada vez que se escanea un dispositivo
        (esto es lo que permite tener historial y comparar cambios).
      - puertos_detectados: los puertos encontrados en cada escaneo, ya
        enriquecidos con nivel de riesgo, descripción y mitigación.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dispositivos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        ip TEXT UNIQUE,
        token_qr TEXT UNIQUE
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS escaneos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dispositivo_id INTEGER,
        fecha TEXT,
        FOREIGN KEY (dispositivo_id) REFERENCES dispositivos(id)
    )""")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS puertos_detectados (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        escaneo_id INTEGER,
        puerto INTEGER,
        servicio TEXT,
        estado TEXT,
        nivel_riesgo TEXT,
        descripcion TEXT,
        mitigacion TEXT,
        FOREIGN KEY (escaneo_id) REFERENCES escaneos(id)
    )""")

    conn.commit()
    conn.close()


def guardar_escaneo(dispositivo_id, resultados_puertos):
    """
    Guarda un nuevo escaneo (con fecha) y todos los puertos encontrados
    en ese escaneo. Devuelve el id del escaneo recién creado.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO escaneos (dispositivo_id, fecha) VALUES (?, ?)",
        (dispositivo_id, datetime.now().isoformat())
    )
    escaneo_id = cursor.lastrowid

    for p in resultados_puertos:
        cursor.execute("""
            INSERT INTO puertos_detectados
            (escaneo_id, puerto, servicio, estado, nivel_riesgo, descripcion, mitigacion)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (escaneo_id, p["puerto"], p["servicio"], p["estado"],
             p.get("nivel_riesgo"), p.get("descripcion"), p.get("mitigacion"))
        )

    conn.commit()
    conn.close()
    return escaneo_id


def comparar_ultimos_escaneos(dispositivo_id):
    """
    Compara el escaneo más reciente de un dispositivo contra el anterior,
    y devuelve la lista de puertos cuyo estado cambió (ej. de closed a open).
    Esto es lo que permite mostrar en vivo "antes vs. ahora" en la demo.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM escaneos WHERE dispositivo_id=?
        ORDER BY id DESC LIMIT 2
    """, (dispositivo_id,))
    escaneos = cursor.fetchall()

    if len(escaneos) < 2:
        conn.close()
        return {"cambios": [], "mensaje": "Aún no hay suficiente historial para comparar."}

    actual_id, anterior_id = escaneos[0][0], escaneos[1][0]

    def obtener_puertos(escaneo_id):
        cursor.execute("SELECT puerto, estado FROM puertos_detectados WHERE escaneo_id=?", (escaneo_id,))
        return {row[0]: row[1] for row in cursor.fetchall()}

    actual = obtener_puertos(actual_id)
    anterior = obtener_puertos(anterior_id)

    cambios = []
    for puerto, estado in actual.items():
        estado_anterior = anterior.get(puerto)
        if estado_anterior != estado:
            cambios.append({"puerto": puerto, "antes": estado_anterior, "ahora": estado})

    conn.close()
    return {"cambios": cambios}


def registrar_dispositivo(nombre, ip, token_qr):
    """
    Inserta un nuevo dispositivo (por ejemplo, uno de los señuelos) en la
    base de datos, con su token QR ya generado.
    """
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO dispositivos (nombre, ip, token_qr) VALUES (?, ?, ?)",
        (nombre, ip, token_qr)
    )
    conn.commit()
    conn.close()


def listar_dispositivos():
    """Devuelve todos los dispositivos registrados como lista de diccionarios."""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, nombre, ip, token_qr FROM dispositivos")
    dispositivos = [
        {"id": r[0], "nombre": r[1], "ip": r[2], "token_qr": r[3]}
        for r in cursor.fetchall()
    ]
    conn.close()
    return dispositivos


def obtener_dispositivo_por_token(token):
    """Busca un dispositivo por su token QR. Devuelve None si no existe."""
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, nombre, ip FROM dispositivos WHERE token_qr=?", (token,))
    fila = cursor.fetchone()
    conn.close()
    if fila is None:
        return None
    return {"id": fila[0], "nombre": fila[1], "ip": fila[2]}


if __name__ == "__main__":
    crear_base_datos()
    print("Base de datos creada correctamente (database.db).")
