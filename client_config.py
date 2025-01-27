class ClientConfig(object):
     # Leer claves manualmente
    with open(".pyupdater/keys/keys.pub", "r") as pub_key_file:
        PUBLIC_KEY = pub_key_file.read()
    APP_NAME = 'Vinder'
    COMPANY_NAME = 'Said_P'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3
    UPDATE_URLS = ['https://github.com/Saidpc18/Flask_stripe_server/releases']
