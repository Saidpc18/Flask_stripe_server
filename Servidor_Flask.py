import os
import json
import logging
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError
import stripe

# Configura el logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Guarda los logs en un archivo
        logging.StreamHandler()          # También muestra los logs en la consola
    ]
)
logger = logging.getLogger(__name__)

# Inicializa Flask
app = Flask(__name__)

# ============================
# CONFIGURA TU CLAVE SECRETA DE STRIPE
# ============================
stripe.api_key = "REDACTED_STRIPE_KEY"  # <-- Asegúrate de usar tu propia clave
webhook_secret = "REDACTED_STRIPE_WEBHOOK_SECRET"  # <-- Asegúrate de usar tu propio webhook secret

# Archivo de usuarios
usuarios_archivo = "usuarios.json"

# ============================
# Clase para validar eventos de Stripe
# ============================
class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)

# ============================
# Funciones de usuarios y licencias
# ============================
def cargar_usuarios():
    try:
        if os.path.exists(usuarios_archivo):
            with open(usuarios_archivo, "r") as f:
                return json.load(f)
        return {}
    except Exception as e:
        logger.error(f"Error al cargar usuarios: {e}")
        return {}

def guardar_usuarios(usuarios):
    try:
        with open(usuarios_archivo, "w") as f:
            json.dump(usuarios, f, indent=4)
    except Exception as e:
        logger.error(f"Error al guardar usuarios: {e}")

def licencia_activa(usuario):
    """
    Verifica si la licencia de un usuario está activa.
    """
    usuarios = cargar_usuarios()
    if usuario not in usuarios:
        return False  # Usuario no encontrado
    licencia = usuarios[usuario].get("license_expiration")
    if not licencia:
        return False  # Licencia no configurada
    return datetime.strptime(licencia, "%Y-%m-%d") > datetime.now()

def renovar_licencia(usuario):
    """
    Renueva la licencia del usuario por un año.
    """
    usuarios = cargar_usuarios()
    if usuario not in usuarios:
        return False  # Usuario no encontrado

    ahora = datetime.now()
    nueva_fecha = ahora + timedelta(days=365)  # Extiende la licencia un año más

    usuarios[usuario]["license_expiration"] = nueva_fecha.strftime("%Y-%m-%d")
    guardar_usuarios(usuarios)
    return True

# ============================
# Webhook de Stripe
# ============================
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Procesa eventos de Stripe enviados al webhook."""
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        logger.info(f"Evento recibido: {event['type']}")

        # Validar el evento recibido
        schema = StripeEventSchema()
        schema.load(event)

        # Manejar eventos específicos
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            logger.info(f"Contenido de la sesión: {session}")
            usuario = session.get("client_reference_id")  # ID del usuario en la sesión

            if usuario:
                logger.info(f"Usuario encontrado: {usuario}")
                # Renovar licencia para el usuario
                if renovar_licencia(usuario):
                    logger.info(f"Licencia renovada para el usuario: {usuario}")
                else:
                    logger.warning(f"Usuario no encontrado: {usuario}")
            else:
                logger.warning("El campo client_reference_id no fue enviado o es None.")

    except ValidationError as e:
        logger.error(f"Datos del evento inválidos: {e.messages}")
        return "Datos del evento inválidos", 400
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Error en la verificación de la firma del webhook: {e}")
        return "Webhook signature verification failed", 400
    except Exception as e:
        logger.error(f"Error general al procesar el webhook: {e}")
        return "Error al procesar el webhook", 500

    return "OK", 200

# ============================
# Endpoint para crear sesión de pago
# ============================
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # Verifica que el cliente haya enviado el campo 'user'
        data = request.json
        if not data or 'user' not in data:
            logger.error("El campo 'user' es requerido pero no fue enviado.")
            return jsonify({"error": "El campo 'user' es requerido para iniciar el proceso de pago."}), 400

        # Extrae el usuario del cuerpo de la solicitud
        user = data['user']

        # Crea la sesión de Stripe Checkout
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': 'price_1QfWXBG4Og1KI6OFQcEYBl8m',  # <-- Reemplaza con tu Price ID real
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url='http://localhost:5000/success',
            cancel_url='http://localhost:5000/cancel',
            client_reference_id=user,  # Vincula el pago al usuario
        )
        logger.info(f"Sesión de pago creada correctamente para el usuario: {user}")
        return jsonify({'url': session.url})

    except Exception as e:
        logger.error(f"Error al crear la sesión de pago: {e}")
        return jsonify({"error": str(e)}), 500

# ============================
# Endpoint para funcionalidades principales
# ============================
@app.route("/funcion-principal", methods=["GET"])
def funcion_principal():
    usuario = request.args.get("user")  # Supongamos que el cliente envía el usuario en la URL
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403
    return jsonify({"message": "Acceso permitido a la función principal."})

# ============================
# Punto de entrada
# ============================
if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Iniciando servidor en el puerto {port}.")
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        logger.critical(f"Error al iniciar el servidor: {e}")
