class ClientConfig(object):
<<<<<<< HEAD
     # Leer claves manualmente
    with open(".pyupdater/keys/keys.pub", "r") as pub_key_file:
        PUBLIC_KEY = pub_key_file.read()
    APP_NAME = 'Vinder'
    COMPANY_NAME = 'Said_P'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3
    UPDATE_URLS = ['https://github.com/Saidpc18/Flask_stripe_server/releases']
=======
    PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1aMERyfzkzqBtkv4Tg/j
G+U5eNNvV9nCmnvYT9SJD+PunYFJVnmcwTgf1kBvh/YjEp7IzzfNzcWFYvjuzrEQ
taiRh1960ox11UZhQa8S8zFv4r7q9qBToBUf8o7XM37Cn+gCTTho+kA1zjuMjmYv
Mt6Py6q4+2yUKIWv+PmQ7vFEPzYzUDkN5hAahPAywkoQOAOgLlB435eQcfIYSOux
YypaC+8VjcN0r3B5xwi+nlmQtOPZTh1MmlJK4uwofvxCjK+zwb7Fo80fekit/cnG
CSI4cdT/YT6/IHTnK16YDaQ18UiAT4rvfsqrPQLLfLBTWvujszWOutHC702FUoxd
qQIDAQAB
-----END PUBLIC KEY-----"""

    APP_NAME = 'Vinder'
    COMPANY_NAME = 'SaidPerales'
    HTTP_TIMEOUT = 30
    MAX_DOWNLOAD_RETRIES = 3
    UPDATE_URLS = ['https://github.com/Saidpc18/Flask_stripe_server/releases', 'https://flask-stripe-server.onrender.com']
>>>>>>> a3481df0d1f43c159e331261ee7bfcd8228f8dfb
