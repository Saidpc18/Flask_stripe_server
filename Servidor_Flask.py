import os
import logging
from datetime import datetime, timedelta
import bcrypt

from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError
import stripe

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

print("DEBUG FILE:", __file__)

# ============================
# CONFIGURACIÓN DE LOGGING
# ============================
logging.basicConfig(
    level=logging.DEBUG,  # Cambia a INFO o WARNING en producción
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),  # Logs en archivo
        logging.StreamHandler()  # Logs en consola
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
    "host": os.getenv("DB_HOST", "junction.proxy.rlwy.net"),
    "port": int(os.getenv("DB_PORT", 19506))
}

print("Configuración de la base de datos:")
print(DB_CONFIG)

app = Flask(__name__)

# Configura DEBUG según la variable de entorno
if os.getenv("FLASK_ENV") == "production":
    app.config["DEBUG"] = False
else:
    app.config["DEBUG"] = True

# Construimos la URL de la BD
default_db_url = (
    f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
    f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}"
)

print(default_db_url)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    "DATABASE_URL",
    default_db_url
)
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


class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)


# ============================
# MODELOS SQLALCHEMY
# ============================
class User(db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    license_expiration = db.Column(db.DateTime, nullable=True)
    secuencial = db.Column(db.Integer, default=0)
    last_year = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

    vins = db.relationship("VIN", backref="owner", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class VIN(db.Model):
    __tablename__ = 'VIN'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)

    vin_completo = db.Column(db.String(17), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f"<VIN {self.vin_completo}>"


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


class YearSequence(db.Model):
    __tablename__ = 'year_sequences'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    secuencial = db.Column(db.Integer, default=1)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'year', name='uq_user_year'),
    )

    def __repr__(self):
        return f"<YearSequence user_id={self.user_id}, year={self.year}, secuencial={self.secuencial}>"


# ============================
# FUNCIONES AUXILIARES
# ============================
def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def license_is_active(user: User) -> bool:
    if not user or not user.license_expiration:
        return False
    return user.license_expiration > datetime.now()


def renew_license(user: User) -> bool:
    if not user:
        return False
    user.license_expiration = datetime.now() + timedelta(days=365)
    db.session.commit()
    return True


def update_secuencial(user: User, year: int) -> int:
    if not user:
        return 0
    if user.last_year != year:
        user.secuencial = 1
        user.last_year = year
    else:
        user.secuencial = user.secuencial + 1 if user.secuencial < 999 else 1
    db.session.commit()
    return user.secuencial


def obtener_o_incrementar_secuencial(username: str, year: int) -> int:
    user = get_user_by_username(username)
    if not user:
        logger.warning(f"Usuario {username} no existe.")
        return 0

    year_seq = YearSequence.query.filter_by(user_id=user.id, year=year).first()

    if not year_seq:
        year_seq = YearSequence(
            user_id=user.id,
            year=year,
            secuencial=1
        )
        db.session.add(year_seq)
        db.session.commit()
        return 1
    else:
        if year_seq.secuencial >= 999:
            year_seq.secuencial = 1
        else:
            year_seq.secuencial += 1

        db.session.commit()
        return year_seq.secuencial


# ============================
# DICCIONARIO DE LETRAS → AÑO (ejemplo)
# ============================
YEAR_MAP = {
    "R": 2024,  # para 2024
    "S": 2025,
    "T": 2026,
    "V": 2027,
    "W": 2028,


# ============================
# RUTAS
# ============================
@app.route("/")
def home():
    return "Bienvenido a la API de VIN Builder (SQLAlchemy Edition)"


@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json(force=True)
    except Exception as e:
        logger.error(f"Error parseando JSON: {e}")
        return jsonify({"error": "JSON inválido"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos."}), 400

    existing = get_user_by_username(username)
    if existing:
        return jsonify({"error": "El usuario ya existe."}), 400

    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)
    hashed_pw_str = hashed_pw.decode('utf-8')

    new_user = User(username=username, password=hashed_pw_str)
    db.session.add(new_user)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al registrar el usuario: {e}")
        return jsonify({"error": "Error al registrar el usuario"}), 500

    return jsonify({"message": "Usuario registrado exitosamente."}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({"message": "Login exitoso"}), 200
    else:
        return jsonify({"error": "Contraseña incorrecta"}), 401


@app.route('/obtener_secuencial', methods=['POST'])
def obtener_secuencial():
    """
    Endpoint para obtener el siguiente secuencial de un usuario por año.
    Puede recibir year como número (2024) o letra (e.g. "R" => 2024).

    JSON esperado: {"user": "username", "year": "R"} o {"year": 2024}
    """
    data = request.json
    username = data.get("user")
    year_value = data.get("year")

    if not username or not year_value:
        return jsonify({"error": "Se requiere 'user' y 'year'"}), 400

    # Intentamos convertir la letra a año si existe en YEAR_MAP
    # De lo contrario, int(...) para pasarlo a entero.
    try:
        if isinstance(year_value, str) and year_value in YEAR_MAP:
            # "R" => 2024
            year_int = YEAR_MAP[year_value]
        else:
            # Convertir year_value a entero directamente
            year_int = int(year_value)
    except ValueError:
        # Si falla la conversión
        return jsonify({"error": f"Valor de 'year' inválido: {year_value}"}), 400

    try:
        nuevo_secuencial = obtener_o_incrementar_secuencial(username, year_int)
        return jsonify({"secuencial": nuevo_secuencial}), 200
    except Exception as e:
        logger.error(f"Error al obtener secuencial: {e}")
        return jsonify({"error": "Error al obtener el secuencial"}), 500


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    logger.debug(f"Encabezado de firma recibido: {sig_header}")
    logger.debug(f"Payload recibido: {payload.decode('utf-8')}")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        logger.info(f"Evento recibido: {event.get('type')}")

        event_type = event.get("type", "")
        event_data = event.get("data", {}).get("object", {})

        if event_type == "checkout.session.completed":
            logger.info(f"Manejando evento: {event_type}")
            session = event_data
            usuario = session.get("client_reference_id")
            if usuario:
                user = get_user_by_username(usuario)
                if renew_license(user):
                    logger.info(f"Licencia renovada para el usuario: {usuario}")
                else:
                    logger.warning(f"Usuario no encontrado: {usuario}")
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


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        data = request.json
        if not data or 'user' not in data:
            logger.error("El campo 'user' es requerido pero no fue enviado.")
            return jsonify({"error": "El campo 'user' es requerido para iniciar el proceso de pago."}), 400

        user = data['user']

        success_url = os.getenv("SUCCESS_URL", "https://flask-stripe-server.onrender.com/success")
        cancel_url = os.getenv("CANCEL_URL", "https://flask-stripe-server.onrender.com/cancel")

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
            error_code = e.error.code
            decline_code = getattr(e.error, 'decline_code', None)

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


@app.route("/success", methods=["GET"])
def success():
    return "¡Pago exitoso! Gracias por tu compra."


@app.route("/cancel", methods=["GET"])
def cancel():
    return "El proceso de pago ha sido cancelado o ha fallado."


@app.route("/funcion-principal", methods=["GET"])
def funcion_principal():
    usuario = request.args.get("user")
    user = get_user_by_username(usuario)
    if not license_is_active(user):
        return jsonify({"error": "Licencia expirada o usuario inexistente. Renueva para continuar."}), 403
    return jsonify({"message": "Acceso permitido a la función principal."})


@app.route('/guardar_vin', methods=['POST'])
def guardar_vin_endpoint():
    print("DEBUG>>> VIN class:", VIN, type(VIN), VIN.__module__)
    print("DEBUG>>> VIN columns:", VIN.__table__.columns.keys())

    data = request.json
    user_name = data.get("user")
    vin_completo = data.get("vin_completo")

    if not user_name or not vin_completo:
        return jsonify({"error": "Faltan datos necesarios (user, vin_completo)"}), 400

    user = get_user_by_username(user_name)
    if not user:
        return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

    print("DEBUG>>>", VIN, type(VIN), VIN.__module__)

    try:
        nuevo_vin = VIN(user_id=user.id, vin_completo=vin_completo)
        db.session.add(nuevo_vin)
        db.session.commit()
        return jsonify({"message": "VIN guardado exitosamente"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al guardar VIN: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/ver_vins', methods=['GET'])
def ver_vins():
    user_name = request.args.get("user")
    if not user_name:
        return jsonify({"error": "Usuario no especificado"}), 400

    user = get_user_by_username(user_name)
    if not user:
        return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

    try:
        vins = user.vins
        resultado = [
            {
                "vin_completo": vin.vin_completo,
                "created_at": vin.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for vin in vins
        ]
        return jsonify({"vins": resultado}), 200
    except Exception as e:
        logger.error(f"Error al listar VINs: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Iniciando servidor en el puerto {port} (DEBUG={app.config['DEBUG']})")
        app.run(host="0.0.0.0", port=port)
    except Exception as e:
        logger.critical(f"Error al iniciar el servidor: {e}")
