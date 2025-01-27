class ClientConfig(object):
        # Ruta al archivo de la clave pública
    PUBLIC_KEY_PATH = '.pyupdater/keys/keys.pub'
    # Inicialmente, PUBLIC_KEY se deja vacío; se llenará al cargar la clave pública
    PUBLIC_KEY = None
    APP_NAME = 'Vinder'
    COMPANY_NAME = 'SaidPerales'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3
    UPDATE_URLS = ['https://github.com/Saidpc18/Flask_stripe_server/releases', 'https://flask-stripe-server.onrender.com']
