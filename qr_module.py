import os
import uuid
import qrcode

CARPETA_QR = os.path.join(os.path.dirname(__file__), "qr_codes")

# Asegura que la carpeta qr_codes/ exista antes de guardar nada ahí.
os.makedirs(CARPETA_QR, exist_ok=True)


def generar_token():
    """
    Genera un identificador corto y único (8 caracteres) para un
    dispositivo, que se usará como parte de la URL del QR.
    Ejemplo de token: 'a1b2c3d4'
    """
    return str(uuid.uuid4())[:8]


def generar_qr(token, url_base):
    """
    Crea la imagen del código QR que, al escanearse, lleva a la tarjeta
    de seguridad del dispositivo correspondiente.

    Args:
        token: el identificador único del dispositivo (ver generar_token()).
        url_base: la URL donde corre el backend el día de la feria,
                   ej. "http://192.168.50.1:5000"
                   IMPORTANTE: debe ser la IP real de la laptop-servidor
                   en la red de la feria, no "localhost" ni "127.0.0.1",
                   para que los celulares del público puedan acceder.

    Returns:
        La URL completa que quedó codificada en el QR.
    """
    url = f"{url_base}/dispositivo/{token}"
    img = qrcode.make(url)

    ruta_archivo = os.path.join(CARPETA_QR, f"{token}.png")
    img.save(ruta_archivo)

    return url


if __name__ == "__main__":
    # Prueba manual: genera un QR de ejemplo para confirmar que todo
    # funciona antes de conectarlo con el resto del sistema.
    token_prueba = generar_token()
    url_generada = generar_qr(token_prueba, url_base="http://192.168.50.1:5000")
    print(f"Token generado: {token_prueba}")
    print(f"URL codificada en el QR: {url_generada}")
    print(f"Imagen guardada en: qr_codes/{token_prueba}.png")
