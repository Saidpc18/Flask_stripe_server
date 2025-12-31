import os


class ClientConfig(object):
    PUBLIC_KEY = 'sJJiVQOxmD7BZ3gBgJYgERPIdNjTOfAoTZekdqu00Ls'
    APP_NAME = 'Vinder'
    COMPANY_NAME = 'SaidPerales'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3

    # ✅ SOLO GitHub Releases (sin Render)
    UPDATE_URLS = [
        'https://github.com/Saidpc18/Flask_stripe_server/releases'
    ]

    # ✅ Backend Railway (opcional pero útil para centralizar)
    # Puedes cambiarlo sin recompilar si tu app lee esta config y/o variable:
    #   setx VINDER_SERVER_URL "https://tu-app.up.railway.app"
    SERVER_BASE = os.getenv(
        "VINDER_SERVER_URL",
        "https://flaskstripeserver-production.up.railway.app"
    ).rstrip("/")
