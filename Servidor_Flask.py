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

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """Procesa eventos de Stripe enviados al webhook."""
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except stripe.error.SignatureVerificationError as e:
        return "Webhook signature verification failed", 400

    # Manejo del evento `checkout.session.completed`
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        usuario = session.get("client_reference_id")  # ID del usuario en la sesión
        usuarios = cargar_usuarios()

        if usuario in usuarios:
            # Renueva la licencia por un año desde la fecha actual
            ahora = datetime.now()
            nueva_fecha = ahora + timedelta(days=365)
            usuarios[usuario]["license_expiration"] = nueva_fecha.strftime("%Y-%m-%d")
            guardar_usuarios(usuarios)

            print(f"Licencia renovada para el usuario: {usuario}")
        else:
            print(f"Usuario no encontrado: {usuario}")

    return "OK", 200

# Ejecuta el servidor
if __name__ == "__main__":
    # Obtén el puerto desde la variable de entorno (por defecto usa 5000)
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
