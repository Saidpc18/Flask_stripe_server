import os
import json
from datetime import datetime, timedelta
from flask import Flask, request
import stripe

# Inicializa Flask
app = Flask(__name__)

# Configura tu clave secreta de Stripe y el webhook secret
stripe.api_key = "Merfosis22"  # Reemplaza con tu clave secreta real
webhook_secret = "REDACTED_STRIPE_WEBHOOK_SECRET"  # Reemplaza con tu webhook secret

# Archivo de usuarios
usuarios_archivo = "usuarios.json"

def cargar_usuarios():
    if os.path.exists(usuarios_archivo):
        with open(usuarios_archivo, "r") as f:
            return json.load(f)
    return {}

def guardar_usuarios(usuarios):
    with open(usuarios_archivo, "w") as f:
        json.dump(usuarios, f, indent=4)

@app.route("/")
def home():
    return "¡Bienvenido! La aplicación Flask está corriendo."

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Procesa eventos de Stripe enviados al webhook."""
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        print(f"Evento recibido: {event['type']}")
    except stripe.error.SignatureVerificationError as e:
        print("Error en la verificación de la firma del webhook:", e)
        return "Webhook signature verification failed", 400

    # Manejo del evento `checkout.session.completed`
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        print(f"Contenido de la sesión: {session}")
        usuario = session.get("client_reference_id")  # ID del usuario en la sesión

        if usuario:
            print(f"Usuario encontrado: {usuario}")
            # Aquí procesas la renovación de licencia
        else:
            print("El campo client_reference_id no fue enviado o es None.")

    # Manejo del evento `charge.updated`
    elif event["type"] == "charge.updated":
        charge = event["data"]["object"]
        print(f"Información de la transacción actualizada: {charge}")

    # Manejo del evento `payment_intent.succeeded`
    elif event["type"] == "payment_intent.succeeded":
        payment_intent = event["data"]["object"]
        print(f"Pago exitoso procesado: {payment_intent}")
        # Aquí puedes agregar lógica adicional para manejar el pago exitoso.

    else:
        print(f"Evento no manejado: {event['type']}")

    return "OK", 200


# Ejecuta el servidor
if __name__ == "__main__":
    # Obtén el puerto desde la variable de entorno (por defecto usa 5000)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
