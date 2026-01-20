# Servidor_Flask.py (PRODUCCIÓN) — completo y corregido
# - Auth por token (Authorization: Bearer ...)
# - No se confía en "user" enviado por el cliente
# - client_id vive en DB y se devuelve en /login y /me
# - Admin endpoint para crear usuarios con client_id (y setearlo)
# - Secretos SOLO por variables de entorno (sin hardcode)
# - Endpoints sensibles protegidos con @require_auth
# - Stripe: create-checkout-session usa usuario autenticado
# - OVERRIDE DE PRUEBAS: PECACAS => client_id "jm" (forzado en backend)
# - URLs default a Railway (sin Render)

import os
import io
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional
import subprocess

import bcrypt
import pandas as pd
import stripe
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Flask, request, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Opcional: si no lo tienes instalado, quita el import y el except correspondiente
from marshmallow import ValidationError


# ============================
# APP
# ============================
app = Flask(__name__)

# ============================
# LOGGING
# ============================
logging.basicConfig(
    level=logging.DEBUG if os.getenv("FLASK_ENV") != "production" else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ============================
# CONFIG PRODUCCIÓN
# ============================
app.config["DEBUG"] = False if os.getenv("FLASK_ENV") == "production" else True

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise ValueError("SECRET_KEY es obligatorio en producción (env var).")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
if not ADMIN_API_KEY:
    logger.warning("ADMIN_API_KEY no está configurado (no podrás usar endpoints /admin/*).")

# ============================
# DB CONFIG
# ============================
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "railway"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
    "host": os.getenv("DB_HOST", ""),
    "port": int(os.getenv("DB_PORT", 5432)),
}

default_db_url = (
    f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}"
    f"@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}"
)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_db_url)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ============================
# STRIPE CONFIG (SOLO ENV VARS)
# ============================
stripe.api_key = os.getenv("STRIPE_API_KEY")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

if not stripe.api_key:
    raise ValueError("STRIPE_API_KEY es obligatorio en producción (env var).")
if not webhook_secret:
    raise ValueError("STRIPE_WEBHOOK_SECRET es obligatorio en producción (env var).")

STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
if not STRIPE_PRICE_ID:
    logger.warning("STRIPE_PRICE_ID no está configurado (no podrás crear checkout session).")

# ============================
# PUBLIC URL (RAILWAY)
# ============================
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://flaskstripeserver-production.up.railway.app").rstrip("/")

SUCCESS_URL = os.getenv("SUCCESS_URL", f"{PUBLIC_BASE_URL}/success")
CANCEL_URL = os.getenv("CANCEL_URL", f"{PUBLIC_BASE_URL}/cancel")

# ============================
# OVERRIDES DE PRUEBAS
# ============================
TEST_CLIENT_OVERRIDES = {
    "PECACAS": "jm",
}

# ============================
# YEAR MAP
# ============================
YEAR_MAP = {
    "R": 2024,
    "S": 2025,
    "T": 2026,
    "V": 2027,
    "W": 2028,
    "P": 2029,
}

# ============================
# MODELOS
# ============================
class User(db.Model):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    client_id = db.Column(db.String(50), nullable=False)  # obligatorio

    license_expiration = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

    vins = db.relationship("VIN", backref="owner", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class VIN(db.Model):
    __tablename__ = "VIN"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    vin_completo = db.Column(db.String(17), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f"<VIN {self.vin_completo}>"


class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(db.String, unique=True, nullable=False)
    customer_id = db.Column(db.String)
    status = db.Column(db.String)
    current_period_end = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

    def __repr__(self):
        return f"<Subscription {self.subscription_id} - {self.status}>"


class YearSequence(db.Model):
    __tablename__ = "year_sequences"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    secuencial = db.Column(db.Integer, default=1)

    __table_args__ = (db.UniqueConstraint("user_id", "year", name="uq_user_year"),)

    def __repr__(self):
        return f"<YearSequence user_id={self.user_id}, year={self.year}, secuencial={self.secuencial}>"


# ============================
# AUTH (TOKEN)
# ============================
def _token_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="vinder-auth")


def create_auth_token(user: User) -> str:
    s = _token_serializer()
    return s.dumps({"uid": user.id})


def get_user_from_token(token: str, max_age_seconds: int = 60 * 60 * 24 * 7) -> Optional[User]:
    s = _token_serializer()
    try:
        data = s.loads(token, max_age=max_age_seconds)
        uid = data.get("uid")
        if not uid:
            return None
        return db.session.get(User, uid)
    except (BadSignature, SignatureExpired):
        return None


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Falta Authorization: Bearer <token>"}), 401
        token = auth.split(" ", 1)[1].strip()
        user = get_user_from_token(token)
        if not user:
            return jsonify({"error": "Token inválido o expirado"}), 401
        request.current_user = user
        return fn(*args, **kwargs)
    return wrapper


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-Admin-Key")
        if not ADMIN_API_KEY or api_key != ADMIN_API_KEY:
            return jsonify({"error": "No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper


# ============================
# HELPERS NEGOCIO
# ============================
def get_user_by_username(username: str) -> Optional[User]:
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


def _apply_test_client_override_if_needed(user: User) -> None:
    try:
        uname = (user.username or "").strip().upper()
        forced_client = TEST_CLIENT_OVERRIDES.get(uname)
        if forced_client and user.client_id != forced_client:
            user.client_id = forced_client
            db.session.commit()
            logger.info(f"[OVERRIDE] Forzado client_id='{forced_client}' para usuario='{uname}'")
    except Exception as e:
        db.session.rollback()
        logger.warning(f"No se pudo aplicar override de client_id para {user.username}: {e}")


def obtener_o_incrementar_secuencial_for_user(user: User, year_input) -> int:
    if not user:
        return 0

    if isinstance(year_input, str) and year_input.isdigit():
        year_int = int(year_input)
    elif isinstance(year_input, str) and year_input in YEAR_MAP:
        year_int = YEAR_MAP[year_input]
    else:
        try:
            year_int = int(year_input)
        except Exception:
            logger.error(f"Valor de año inválido: {year_input}")
            return 0

    year_seq = YearSequence.query.filter_by(user_id=user.id, year=year_int).first()
    if not year_seq:
        year_seq = YearSequence(user_id=user.id, year=year_int, secuencial=1)
        db.session.add(year_seq)
        db.session.commit()
        return 1

    year_seq.secuencial = 1 if year_seq.secuencial >= 999 else (year_seq.secuencial + 1)
    db.session.commit()
    return year_seq.secuencial


# ============================
# ROUTES
# ============================
@app.route("/")
def home():
    return "Bienvenido a la API de Vinder (Producción - Railway)"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "vinder-api"}), 200


@app.route("/me", methods=["GET"])
@require_auth
def me():
    user = request.current_user
    return jsonify({
        "username": user.username,
        "client_id": user.client_id,
        "license_active": license_is_active(user),
        "license_expiration": user.license_expiration.isoformat() if user.license_expiration else None,
    }), 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    if not bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
        return jsonify({"error": "Contraseña incorrecta"}), 401

    _apply_test_client_override_if_needed(user)

    token = create_auth_token(user)
    return jsonify({
        "message": "Login exitoso",
        "token": token,
        "client_id": user.client_id,
    }), 200


@app.route("/admin/create_user", methods=["POST"])
@require_admin
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    client_id = (data.get("client_id") or "").strip()

    if not username or not password:
        return jsonify({"error": "username y password son requeridos"}), 400

    if not client_id and username.upper() in TEST_CLIENT_OVERRIDES:
        client_id = TEST_CLIENT_OVERRIDES[username.upper()]

    if not client_id:
        return jsonify({"error": "client_id es requerido"}), 400

    if get_user_by_username(username):
        return jsonify({"error": "El usuario ya existe"}), 400

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    new_user = User(username=username, password=hashed_pw, client_id=client_id)
    db.session.add(new_user)
    db.session.commit()

    _apply_test_client_override_if_needed(new_user)

    return jsonify({
        "message": "Usuario creado",
        "username": new_user.username,
        "client_id": new_user.client_id
    }), 201


@app.route("/admin/set_user_client_id", methods=["POST"])
@require_admin
def admin_set_user_client_id():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    client_id = (data.get("client_id") or "").strip()

    if not username or not client_id:
        return jsonify({"error": "username y client_id son requeridos"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    try:
        user.client_id = client_id
        db.session.commit()
        _apply_test_client_override_if_needed(user)
        return jsonify({"message": "client_id actualizado", "username": user.username, "client_id": user.client_id}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error actualizando client_id para {username}: {e}")
        return jsonify({"error": "No se pudo actualizar client_id"}), 500


@app.route("/funcion-principal", methods=["GET"])
@require_auth
def funcion_principal():
    user = request.current_user
    if not license_is_active(user):
        return jsonify({"error": "Licencia expirada. Renueva para continuar."}), 403
    return jsonify({"message": "Acceso permitido"}), 200


@app.route("/obtener_secuencial", methods=["POST"])
@require_auth
def obtener_secuencial():
    data = request.get_json(silent=True) or {}
    year_value = data.get("year")
    if not year_value:
        return jsonify({"error": "Se requiere 'year'"}), 400

    user = request.current_user
    try:
        nuevo = obtener_o_incrementar_secuencial_for_user(user, year_value)
        if nuevo == 0:
            return jsonify({"error": "Año inválido"}), 400
        return jsonify({"secuencial": nuevo}), 200
    except Exception as e:
        logger.error(f"Error al obtener secuencial: {e}")
        return jsonify({"error": "Error al obtener el secuencial"}), 500


@app.route("/guardar_vin", methods=["POST"])
@require_auth
def guardar_vin_endpoint():
    data = request.get_json(silent=True) or {}
    vin_completo = (data.get("vin_completo") or "").strip()
    if not vin_completo:
        return jsonify({"error": "Falta vin_completo"}), 400

    user = request.current_user
    try:
        nuevo_vin = VIN(user_id=user.id, vin_completo=vin_completo)
        db.session.add(nuevo_vin)
        db.session.commit()
        return jsonify({"message": "VIN guardado"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al guardar VIN: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/ver_vins", methods=["GET"])
@require_auth
def ver_vins():
    user = request.current_user
    try:
        vins = VIN.query.filter_by(user_id=user.id).order_by(VIN.created_at.desc()).all()
        resultado = [{"vin_completo": v.vin_completo, "created_at": v.created_at.strftime("%Y-%m-%d %H:%M:%S")} for v in vins]
        return jsonify({"vins": resultado}), 200
    except Exception as e:
        logger.error(f"Error al listar VINs: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/export_vins", methods=["GET"])
@require_auth
def export_vins():
    user = request.current_user
    try:
        vins = VIN.query.filter_by(user_id=user.id).order_by(VIN.created_at.desc()).all()
        data = [{"VIN": v.vin_completo, "Fecha de Creación": v.created_at.strftime("%Y-%m-%d %H:%M:%S")} for v in vins]

        df = pd.DataFrame(data)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="VINs")
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name="vins.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except Exception as e:
        logger.error(f"Error al exportar VINs: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/eliminar_todos_vins", methods=["POST"])
@require_auth
def eliminar_todos_vins():
    user = request.current_user
    if not license_is_active(user):
        return jsonify({"error": "Licencia expirada. Renueva para continuar."}), 403

    try:
        VIN.query.filter_by(user_id=user.id).delete()
        YearSequence.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({"message": "Todos los VINs eliminados y secuencial reiniciado"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar todos los VINs: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/eliminar_ultimo_vin", methods=["POST"])
@require_auth
def eliminar_ultimo_vin():
    user = request.current_user
    if not license_is_active(user):
        return jsonify({"error": "Licencia expirada. Renueva para continuar."}), 403

    try:
        ultimo_vin = VIN.query.filter_by(user_id=user.id).order_by(VIN.created_at.desc()).first()
        if not ultimo_vin:
            return jsonify({"error": "No hay VINs para eliminar"}), 404

        vin_str = (ultimo_vin.vin_completo or "").strip()
        if len(vin_str) != 17:
            return jsonify({"error": "VIN con formato inesperado"}), 500

        year_letter = vin_str[9]
        if year_letter not in YEAR_MAP:
            return jsonify({"error": "VIN no contiene código de año válido"}), 500

        year_int = YEAR_MAP[year_letter]
        year_seq = YearSequence.query.filter_by(user_id=user.id, year=year_int).first()

        if year_seq and year_seq.secuencial > 1:
            year_seq.secuencial -= 1

        db.session.delete(ultimo_vin)
        db.session.commit()
        return jsonify({"message": "Último VIN eliminado y secuencial actualizado"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar el último VIN: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/create-checkout-session", methods=["POST"])
@require_auth
def create_checkout_session():
    user = request.current_user

    if not STRIPE_PRICE_ID:
        return jsonify({"error": "STRIPE_PRICE_ID no configurado en el servidor"}), 500

    try:
        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
            client_reference_id=user.username,
        )
        return jsonify({"url": session_obj.url}), 200
    except stripe.error.CardError as e:
        return jsonify({"error": e.user_message or "La tarjeta fue rechazada"}), 402
    except Exception as e:
        logger.error(f"Error al crear checkout session: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        event_type = event.get("type", "")
        event_data = event.get("data", {}).get("object", {})

        if event_type == "checkout.session.completed":
            session = event_data
            usuario = session.get("client_reference_id")
            if usuario:
                user = get_user_by_username(usuario)
                if user:
                    renew_license(user)

        return jsonify({"status": "success"}), 200

    except ValidationError as e:
        logger.error(f"Datos del evento inválidos: {getattr(e, 'messages', str(e))}")
        return jsonify({"error": "Datos del evento inválidos"}), 400
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Firma inválida webhook: {e}")
        return jsonify({"error": "Firma del webhook inválida"}), 400
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return jsonify({"error": "Error al procesar webhook"}), 400


@app.route("/success", methods=["GET"])
def success():
    return "¡Pago exitoso! Gracias por tu compra."


@app.route("/cancel", methods=["GET"])
def cancel():
    return "El proceso de pago fue cancelado o falló."


@app.route("/check_updates", methods=["GET"])
@require_admin
def check_updates():
    def generate():
        try:
            yield "data: Configurando repositorio de actualizaciones...\n\n"
            subprocess.run(["tufup", "init"], check=True)
            yield "data: Repositorio configurado.\n\n"

            yield "data: Verificando actualizaciones...\n\n"
            result = subprocess.run(["tufup", "targets"], capture_output=True, text=True, check=True)
            yield f"data: Resultado: {result.stdout}\n\n"
        except Exception as e:
            yield f"data: Error: {e}\n\n"

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Iniciando servidor en el puerto {port} (DEBUG={app.config['DEBUG']})")
    app.run(host="0.0.0.0", port=port)
