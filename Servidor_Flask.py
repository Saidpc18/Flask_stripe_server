import os
import logging
from datetime import datetime, timedelta
import bcrypt

from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError
import stripe
import psycopg2

# Flask-SQLAlchemy y Flask-Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# ============================
# CONFIGURACIÓN DE LOGGING
# ============================
logging.basicConfig(
    level=logging.DEBUG,  # Cambia a INFO o WARNING en producción
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Logs en archivo
        logging.StreamHandler()          # Logs en consola
    ]
)
logger = logging.getLogger(__name__)

# ============================
# CONFIGURACIÓN DE LA BASE DE DATOS
# ============================
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "railway"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "woTCfdaWchoxcsKAmCaAxOBzHusEdLLj"),
    "host": os.getenv("DB_HOST", "postgres.railway.internal"),
    "port": int(os.getenv("DB_PORT", 5432))
}

def conectar_bd():
    try:
        return psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Error al conectar con la base de datos: {e}")
        raise

print("Configuración de la base de datos:")
print(DB_CONFIG)

# ============================
# INICIALIZA FLASK
# ============================
app = Flask(__name__)

# Configura DEBUG según la variable de entorno
if os.getenv("FLASK_ENV") == "production":
    app.config["DEBUG"] = False
else:
    app.config["DEBUG"] = True

# ============================
# CONFIGURACIÓN PARA FLASK-SQLALCHEMY
# (para la tabla 'subscriptions' y posibles futuras migraciones)
# ============================
default_db_url = (
    f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
    f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}"
)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "postgresql://postgres:woTCfdaWchoxcsKAmCaAxOBzHusEdLLj@junction.proxy.rlwy.net:19506/railway")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ============================
# CONFIGURACIÓN DE STRIPE
# ============================
stripe.api_key = os.getenv(
    "STRIPE_API_KEY",
    "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"
)
webhook_secret = os.getenv(
    "STRIPE_WEBHOOK_SECRET",
    "whsec_4QAnSKkUNDYAoOSfmURtHNelKARrQw5k"
)

if not webhook_secret:
    logger.error("El secreto del webhook no está configurado.")
    raise ValueError("Stripe Webhook Secret es obligatorio.")



# ============================
# ESQUEMA OPCIONAL PARA VALIDAR EVENTOS DE STRIPE
# ============================
class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)

# ============================
# FUNCIONES DE USUARIOS (psycopg2)
# ============================
def cargar_usuarios():
    """
    Devuelve un dict con todos los usuarios de la tabla 'usuarios':
    {
      "username": {
        "password": ...,
        "license_expiration": ...,
        "secuencial": ...
      },
      ...
    }
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
    Actualiza el usuario dado con el dict `datos`:
    {
      "password": str,
      "license_expiration": str,
      "secuencial": int
    }
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
    Verifica si la licencia de un usuario está activa.
    Retorna True si la fecha de expiración es mayor a la fecha actual.
    """
    todos = cargar_usuarios()
    if usuario not in todos:
        return False

    licencia = todos[usuario].get("license_expiration")
    if not licencia:
        return False

    return datetime.strptime(licencia, "%Y-%m-%d") > datetime.now()

def renovar_licencia(usuario):
    """
    Renueva la licencia del usuario por 365 días.
    Retorna True si el usuario existe y se actualizó correctamente.
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

# ============================
# FUNCIONES PARA VINs (psycopg2)
# ============================
def obtener_user_id(username):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None

def guardar_vin(username, vin_data):
    """
    Inserta un nuevo VIN en la tabla 'vins'.
    Retorna False si el usuario no existe.
    vin_data: {
      "c4": ...,
      "c5": ...,
      "c6": ...,
      "c7": ...,
      "c8": ...,
      "c10": ...,
      "c11": ...,
      "secuencial": ...
    }
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
        c4, c5, c6, c7, c8, c10, c11, sec, created_at = row
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

# ============================
# EJEMPLO DE MODELO CON SQLALCHEMY (para migraciones)
# ============================
class Subscription(db.Model):
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(db.String, unique=True, nullable=False)
    customer_id = db.Column(db.String)
    status = db.Column(db.String)
    current_period_end = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

    def __repr__(self):
        return f"<Subscription {self.subscription_id} - {self.status}>"

# ============================
# RUTAS
# ============================
@app.route("/")
def home():
    return "Bienvenido a la API de VIN Builder"


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos."}), 400

    # Comprueba si el usuario ya existe usando la función cargar_usuarios()
    usuarios = cargar_usuarios()
    if username in usuarios:
        return jsonify({"error": "El usuario ya existe."}), 400

    # Genera la sal y hazhea la contraseña
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)  # resultado es bytes
    hashed_pw_str = hashed_pw.decode('utf-8')  # se almacena como cadena

    try:
        conn = conectar_bd()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO usuarios (username, password, license_expiration, secuencial)
            VALUES (%s, %s, %s, %s)
            """,
            (username, hashed_pw_str, None, 0)  # Por ejemplo, sin licencia inicial y secuencial = 0
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Error al registrar el usuario: {e}")
        return jsonify({"error": "Error al registrar el usuario"}), 500

    return jsonify({"message": "Usuario registrado exitosamente."}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")  # en texto plano

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos"}), 400

    usuarios = cargar_usuarios()  # esta función devuelve un dict de usuarios
    if username not in usuarios:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Suponiendo que la contraseña almacenada es un hash generado con bcrypt
    stored_hash = usuarios[username]["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        return jsonify({"message": "Login exitoso"}), 200
    else:
        return jsonify({"error": "Contraseña incorrecta"}), 401


# ============================
# WEBHOOK DE STRIPE
# ============================
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """
    Maneja los eventos de Stripe usando la validación de firma con stripe.Webhook.construct_event().
    """
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    # Logs de depuración
    logger.debug(f"Encabezado de firma recibido: {sig_header}")
    logger.debug(f"Payload recibido: {payload.decode('utf-8')}")

    try:
        # Validar firma
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        logger.info(f"Evento recibido: {event.get('type')}")

        event_type = event.get("type", "")
        event_data = event.get("data", {}).get("object", {})

        # Manejo de eventos
        if event_type == "checkout.session.completed":
            logger.info(f"Manejando evento: {event_type}")
            session = event_data
            usuario = session.get("client_reference_id")
            if usuario:
                if renovar_licencia(usuario):
                    logger.info(f"Licencia renovada para el usuario: {usuario}")
                else:
                    logger.warning(f"Usuario no encontrado en la base de datos: {usuario}")
            else:
                logger.warning("El campo 'client_reference_id' no fue enviado.")

        elif event_type == "payment_intent.succeeded":
            logger.info(f"Manejando evento: {event_type}")
            payment_intent = event_data
            logger.info(f"PaymentIntent completado: {payment_intent.get('id')}")

        elif event_type in ["product.created", "price.created"]:
            logger.info(f"Manejando evento: {event_type}")

        elif event_type == "charge.succeeded":
            logger.info(f"Manejando evento: {event_type}")
            charge = event_data
            logger.info(f"Cargo exitoso: {charge.get('id')}")

        elif event_type == "charge.updated":
            logger.info(f"Manejando evento: {event_type}")
            charge = event_data
            logger.info(f"Cargo actualizado: {charge.get('id')}")

        else:
            logger.warning(f"Evento no manejado: {event_type}")

        return jsonify({"status": "success"}), 200

    except ValidationError as e:
        logger.error(f"Datos del evento inválidos: {e.messages}")
        return jsonify({"error": "Datos del evento inválidos"}), 400
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Error de firma del webhook: {e}")
        return jsonify({"error": "Firma del webhook inválida"}), 400
    except Exception as e:
        logger.error(f"Error procesando el webhook: {e}")
        return jsonify({"error": "Error al procesar el webhook"}), 400

# ============================
# ENDPOINT PARA CREAR SESIÓN DE PAGO
# ============================
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    """
    Crea una sesión de pago de Stripe y devuelve la URL de Checkout.
    Espera un JSON con {"user": "nombre_usuario"}.
    """
    try:
        data = request.json
        if not data or 'user' not in data:
            logger.error("El campo 'user' es requerido pero no fue enviado.")
            return jsonify({"error": "El campo 'user' es requerido para iniciar el proceso de pago."}), 400

        user = data['user']

        success_url = os.getenv("SUCCESS_URL", "https://flask-stripe-server.onrender.com/success")
        cancel_url = os.getenv("CANCEL_URL", "https://flask-stripe-server.onrender.com/cancel")

        # Manejo de errores de tarjeta al crear la sesión
        try:
            session_obj = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[
                    {
                        'price': 'price_1QfWXBG4Og1KI6OFQcEYBl8m',
                        'quantity': 1,
                    },
                ],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                client_reference_id=user,
            )
        except stripe.error.CardError as e:
            # Manejo de errores de tarjeta (código 402)
            error_code = e.error.code  # p. ej. 'card_declined'
            decline_code = getattr(e.error, 'decline_code', None)  # p. ej. 'insufficient_funds'

            if error_code == "card_declined":
                if decline_code == "insufficient_funds":
                    user_message = "Fondos insuficientes en la tarjeta. Usa otra."
                elif decline_code == "lost_card":
                    user_message = "Tarjeta reportada como perdida. Usa otra."
                elif decline_code == "stolen_card":
                    user_message = "Tarjeta reportada como robada. Usa otra."
                else:
                    user_message = "La tarjeta fue rechazada. Contacta a tu banco."
            else:
                user_message = f"Error de tarjeta: {e.error.message}"

            logger.error(f"Pago fallido: {error_code} - {decline_code} - {user_message}")
            return jsonify({"error": user_message}), 402

        logger.info(f"Sesión de pago creada correctamente para el usuario: {user}")
        return jsonify({'url': session_obj.url})

    except Exception as e:
        logger.error(f"Error al crear la sesión de pago: {e}")
        return jsonify({"error": str(e)}), 500

# ============================
# RUTAS PARA SUCCESS Y CANCEL
# ============================
@app.route("/success", methods=["GET"])
def success():
    return "¡Pago exitoso! Gracias por tu compra."

@app.route("/cancel", methods=["GET"])
def cancel():
    return "El proceso de pago ha sido cancelado o ha fallado."

# ============================
# FUNCIONALIDADES PRINCIPALES
# ============================
@app.route("/funcion-principal", methods=["GET"])
def funcion_principal():
    """
    Verifica si un usuario tiene licencia activa y retorna un mensaje de acceso.
    Espera ?user=USERNAME en la query string.
    """
    usuario = request.args.get("user")
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403
    return jsonify({"message": "Acceso permitido a la función principal."})

@app.route("/guardar_vin", methods=["POST"])
def guardar_vin_endpoint():
    """
    Guarda un nuevo VIN de un usuario.
    Espera un JSON con {"user": "username", "vin_data": {...}}.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No se proporcionaron datos."}), 400

    username = data.get("user")
    vin_data = data.get("vin_data")
    if not username or not vin_data:
        return jsonify({"error": "Faltan 'user' o 'vin_data'"}), 400

    if not licencia_activa(username):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403

    exito = guardar_vin(username, vin_data)
    if not exito:
        return jsonify({"error": "No se pudo guardar el VIN (usuario no existe)."}), 404

    return jsonify({"message": "VIN guardado correctamente."})

@app.route("/ver_vins", methods=["GET"])
def ver_vins():
    """
    Lista los VINs de un usuario. Espera ?user=USERNAME en la query string.
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
