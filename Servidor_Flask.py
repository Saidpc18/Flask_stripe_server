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
# (USA TU PROPIA CLAVE "sk_live_..." o "sk_test_...")
# ============================
stripe.api_key = "REDACTED_STRIPE_KEY"  # <-- Asegúrate de usar tu propia clave
webhook_secret = "REDACTED_STRIPE_WEBHOOK_SECRET"  # <-- Asegúrate de usar tu propio webhook secret

# Archivo de usuarios
usuarios_archivo = "usuarios.json"

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

# Esquema para validar eventos de Stripe
class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)

@app.route("/")
def home():
    logger.info("Endpoint principal '/' accedido.")
    return "¡Bienvenido! La aplicación Flask está corriendo."

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
                # Aquí procesas la renovación de licencia
                # Por ejemplo:
                # usuarios = cargar_usuarios()
                # # Actualizar licencia del usuario
                # guardar_usuarios(usuarios)
            else:
                logger.warning("El campo client_reference_id no fue enviado o es None.")

        elif event["type"] == "charge.updated":
            charge = event["data"]["object"]
            logger.info(f"Información de la transacción actualizada: {charge}")

        elif event["type"] == "payment_intent.succeeded":
            payment_intent = event["data"]["object"]
            logger.info(f"Pago exitoso procesado: {payment_intent}")

        elif event["type"] == "customer.created":
            customer = event["data"]["object"]
            logger.info(f"Nuevo cliente creado: {customer}")

        elif event["type"] == "charge.succeeded":
            charge = event["data"]["object"]
            logger.info(f"Pago completado con éxito: {charge}")

        else:
            logger.warning(f"Evento no manejado: {event['type']}")

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

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        # ============================
        # Opción 1: Usar Price ID
        # ============================
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    'price': 'price_1QfWXBG4Og1KI6OFQcEYBl8m',  # <-- Reemplaza con tu Price ID real
                    'quantity': 1,
                },
            ],
            mode='payment',
            success_url='http://localhost:5000/success',  # <-- Ajusta URLs según tu necesidad
            cancel_url='http://localhost:5000/cancel',
            # Opcional: Si quieres identificar al usuario
            # client_reference_id='usuario_ejemplo'
        )
        return jsonify({'url': session.url})
    except Exception as e:
        logger.error(f"Error al crear la sesión de pago: {e}")
        return jsonify({"error": str(e)}), 500

# Ejecuta el servidor
if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Iniciando servidor en el puerto {port}.")
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        logger.critical(f"Error al iniciar el servidor: {e}")

