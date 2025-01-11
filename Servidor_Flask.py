import os
import json
import logging
from datetime import datetime, timedelta
from flask import Flask, request
from marshmallow import Schema, fields, ValidationError
import stripe

# Configura el logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Guarda los logs en un archivo
        logging.StreamHandler()  # También muestra los logs en la consola
    ]
)
logger = logging.getLogger(__name__)

# Inicializa Flask
app = Flask(__name__)

# Configura tu clave secreta de Stripe y el webhook secret
stripe.api_key = "Merfosis22"  # Reemplaza con tu clave secreta real
webhook_secret = "whsec_8cebd49390f65f43a051b1bd0d86dad809df237674cda13dcbb0f7c6ffd67442"  # Reemplaza con tu webhook secret

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
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Error en la verificación de la firma del webhook: {e}")
        return "Webhook signature verification failed", 400
    except Exception as e:
        logger.error(f"Error general al procesar el webhook: {e}")
        return "Error al procesar el webhook", 500

    # Validar el evento recibido
    try:
        schema = StripeEventSchema()
        schema.load(event)
    except ValidationError as e:
        logger.error(f"Datos del evento inválidos: {e.messages}")
        return "Datos del evento inválidos", 400

    # Manejar eventos específicos
    try:
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            logger.info(f"Contenido de la sesión: {session}")
            usuario = session.get("client_reference_id")  # ID del usuario en la sesión

            if usuario:
                logger.info(f"Usuario encontrado: {usuario}")
                # Aquí procesas la renovación de licencia
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

    except Exception as e:
        logger.error(f"Error al manejar el evento: {e}")
        return "Error al manejar el evento", 500

    return "OK", 200

# Ejecuta el servidor
if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Iniciando servidor en el puerto {port}.")
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        logger.critical(f"Error al iniciar el servidor: {e}")
