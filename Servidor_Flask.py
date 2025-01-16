import os
import json
import logging
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError
import stripe

import psycopg2
from psycopg2.extras import Json

# ============================
# CONFIGURACIÓN DE LA BASE DE DATOS
# ============================
# Usa las variables de entorno para producción.
# Puedes definir valores por defecto para desarrollo, pero asegúrate de usar valores seguros en producción.

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vindatabase"),
    "user": os.getenv("DB_USER", "vindatabase_owner"),
    "password": os.getenv("DB_PASSWORD", "vindatabase_owner"),  # Ajusta en producción (no uses 'owner')
    "host": os.getenv("DB_HOST", "ep-solitary-frost-a5hss4fj.us-east-2.aws.neon.tech"),
    "port": int(os.getenv("DB_PORT", 5432))
}


def conectar_bd():
    """Crea una conexión a la base de datos usando DB_CONFIG."""
    return psycopg2.connect(**DB_CONFIG)


# ============================
# LOGGING
# ============================
# Ajusta el nivel de logs según el entorno. En producción, puedes usar WARNING para reducir la salida de logs.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Guarda logs en un archivo
        logging.StreamHandler()          # Muestra logs en la consola
    ]
)
logger = logging.getLogger(__name__)

# ============================
# INICIALIZA FLASK
# ============================
app = Flask(__name__)

# Configuración del modo de depuración (DEBUG) según el entorno
if os.getenv("FLASK_ENV") == "production":
    app.config["DEBUG"] = False
else:
    app.config["DEBUG"] = True


# ============================
# CONFIGURA STRIPE
# ============================
# En producción, es mejor usar variables de entorno para STRIPE_API_KEY y STRIPE_WEBHOOK_SECRET.
# Si no existen, tomará estos valores por defecto.
stripe.api_key = os.getenv("STRIPE_API_KEY", "sk_live_51QfUyj...")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_4QAnSKkUNDY...")

# ============================
#  CLASE PARA VALIDAR EVENTOS DE STRIPE
# ============================
class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)


# =================================================
# FUNCIONES PARA OBTENER Y ADMINISTRAR USUARIOS
# =================================================
def cargar_usuarios():
    """
    Carga todos los usuarios de la tabla 'usuarios' y los
    devuelve como un dict { username: {...}, ... } con la info de cada usuario.
    """
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT username, password, license_expiration, secuencial FROM usuarios;")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    usuarios = {}
    for row in rows:
        username, password, license_exp, secuencial = row
        usuarios[username] = {
            "password": password,
            "license_expiration": license_exp.strftime("%Y-%m-%d") if license_exp else None,
            "secuencial": secuencial
        }
    return usuarios


def actualizar_usuario(usuario, datos):
    """
    Actualiza un usuario en la tabla 'usuarios'.
    datos = { "password": str, "license_expiration": str, "secuencial": int }
    """
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE usuarios
        SET password = %s,
            license_expiration = %s,
            secuencial = %s
        WHERE username = %s
        """,
        (
            datos["password"],
            datos["license_expiration"],
            datos["secuencial"],
            usuario
        )
    )
    conn.commit()
    cur.close()
    conn.close()


def licencia_activa(usuario):
    """
    Verifica si la licencia de un usuario está activa en la BD.
    Retorna True/False.
    """
    todos = cargar_usuarios()
    if usuario not in todos:
        return False  # Usuario no existe

    licencia = todos[usuario].get("license_expiration")
    if not licencia:
        return False  # No tiene fecha de licencia

    return datetime.strptime(licencia, "%Y-%m-%d") > datetime.now()


def renovar_licencia(usuario):
    """
    Renueva la licencia del usuario por un año.
    Retorna True si se renueva con éxito, False si el usuario no existe.
    """
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT username FROM usuarios WHERE username = %s", (usuario,))
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return False

    nueva_fecha = datetime.now() + timedelta(days=365)
    cur.execute(
        """
        UPDATE usuarios
        SET license_expiration = %s
        WHERE username = %s
        """,
        (nueva_fecha, usuario)
    )
    conn.commit()
    cur.close()
    conn.close()
    return True


# ===================================================
# FUNCIONES PARA ADMINISTRAR VINs EN TABLA SEPARADA
# ===================================================
def obtener_user_id(username):
    """
    Devuelve el id (int) de la tabla 'usuarios' para el username dado,
    o None si no existe.
    """
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None


def guardar_vin(username, vin_data):
    """
    Inserta un nuevo VIN en la tabla 'vins'. Retorna False si el usuario no existe.
    vin_data: { c4, c5, c6, c7, c8, c10, c11, secuencial }
    """
    owner_id = obtener_user_id(username)
    if not owner_id:
        return False

    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO vins (owner_id, c4, c5, c6, c7, c8, c10, c11, secuencial)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            owner_id,
            vin_data["c4"],
            vin_data["c5"],
            vin_data["c6"],
            vin_data["c7"],
            vin_data["c8"],
            vin_data["c10"],
            vin_data["c11"],
            vin_data["secuencial"]
        )
    )
    conn.commit()
    cur.close()
    conn.close()
    return True


def listar_vins(username):
    """
    Retorna una lista de diccionarios con todos los VINs de un usuario.
    """
    owner_id = obtener_user_id(username)
    if not owner_id:
        return []

    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c4, c5, c6, c7, c8, c10, c11, secuencial, created_at
        FROM vins
        WHERE owner_id = %s
        ORDER BY created_at ASC
        """,
        (owner_id,)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    vin_list = []
    for row in rows:
        (c4, c5, c6, c7, c8, c10, c11, sec, created_at) = row
        vin_list.append({
            "c4": c4,
            "c5": c5,
            "c6": c6,
            "c7": c7,
            "c8": c8,
            "c10": c10,
            "c11": c11,
            "secuencial": sec,
            "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return vin_list


@app.route("/")
def home():
    return "Bienvenido a la API de VIN Builder"


# ============================
# WEBHOOK DE STRIPE
# ============================
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        logger.info(f"Evento recibido: {event['type']}")

        schema = StripeEventSchema()
        schema.load(event)

        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            logger.info(f"Contenido de la sesión: {session}")
            usuario = session.get("client_reference_id")

            if usuario:
                logger.info(f"Usuario encontrado: {usuario}")
                if renovar_licencia(usuario):
                    logger.info(f"Licencia renovada para el usuario: {usuario}")
                else:
                    logger.warning(f"Usuario no encontrado en BD: {usuario}")
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
# ENDPOINT PARA CREAR SESIÓN DE PAGO
# ============================
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        data = request.json
        if not data or 'user' not in data:
            logger.error("El campo 'user' es requerido pero no fue enviado.")
            return jsonify({"error": "El campo 'user' es requerido para iniciar el proceso de pago."}), 400

        user = data['user']

        # Cambia localhost a tu dominio en producción
        success_url = os.getenv("SUCCESS_URL", "http://localhost:5000/success")
        cancel_url = os.getenv("CANCEL_URL", "http://localhost:5000/cancel")

        session_obj = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[
                {
                    # Ajusta con tu Price ID real en Stripe
                    'price': 'price_1QfWXBG4Og1KI6OFQcEYBl8m',
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=user,
        )
        logger.info(f"Sesión de pago creada correctamente para el usuario: {user}")
        return jsonify({'url': session_obj.url})

    except Exception as e:
        logger.error(f"Error al crear la sesión de pago: {e}")
        return jsonify({"error": str(e)}), 500


# ============================
# ENDPOINT PARA FUNCIONALIDADES PRINCIPALES
# ============================
@app.route("/funcion-principal", methods=["GET"])
def funcion_principal():
    usuario = request.args.get("user")
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403
    return jsonify({"message": "Acceso permitido a la función principal."})


# ============================
# ENDPOINT PARA GUARDAR UN VIN
# ============================
@app.route("/guardar_vin", methods=["POST"])
def guardar_vin_endpoint():
    """
    Guarda un nuevo VIN de un usuario.
    Espera un JSON:
    {
       "user": "username",
       "vin_data": {
           "c4": ...,
           "c5": ...,
           "c6": ...,
           "c7": ...,
           "c8": ...,
           "c10": ...,
           "c11": ...,
           "secuencial": ...
       }
    }
    """
    data = request.json
    if not data:
        return jsonify({"error": "No se proporcionaron datos."}), 400

    username = data.get("user")
    vin_data = data.get("vin_data")

    if not username or not vin_data:
        return jsonify({"error": "Faltan 'user' o 'vin_data'"}), 400

    # Verificar licencia antes de permitir guardar VIN
    if not licencia_activa(username):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403

    exito = guardar_vin(username, vin_data)
    if not exito:
        return jsonify({"error": "No se pudo guardar el VIN (usuario no existe)."}), 404

    return jsonify({"message": "VIN guardado correctamente."})


# ============================
# ENDPOINT PARA VER VINs DE UN USUARIO
# ============================
@app.route("/ver_vins", methods=["GET"])
def ver_vins():
    """
    Muestra los VINs de un usuario. Recibe ?user=USERNAME
    """
    usuario = request.args.get("user")
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403

    vin_list = listar_vins(usuario)
    return jsonify({"vins": vin_list})


# ============================
# PUNTO DE ENTRADA
# ============================
if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Iniciando servidor en el puerto {port} (DEBUG={app.config['DEBUG']})")
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        logger.critical(f"Error al iniciar el servidor: {e}")
