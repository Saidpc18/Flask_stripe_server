import os

class ClientConfig(object):
    # Leer claves manualmente con verificación de existencia
    try:
        with open(".pyupdater/keys/keys.pub", "r") as pub_key_file:
            PUBLIC_KEY = pub_key_file.read()
    except FileNotFoundError:
        PUBLIC_KEY = None  # O maneja el error según sea necesario

    # Configuración de la aplicación
    APP_NAME = 'Vinder'
    COMPANY_NAME = 'SaidPerales'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3
    UPDATE_URLS = [
        'https://github.com/Saidpc18/Flask_stripe_server/releases',
        'https://flask-stripe-server.onrender.com'
    ]
