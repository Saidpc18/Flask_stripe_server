# Servidor_Flask.py (PRODUCCIÓN) — Railway (CORREGIDO)
# - UTC en todo (licencias/expiraciones)
# - NO db.create_all() en producción (solo opcional en dev)
# - Stripe webhook más robusto: valida subscripción y usa metadata username
# - Overrides de pruebas SOLO fuera de production
# - /check_updates deshabilitado por default (habilítalo con env si lo necesitas)

import os
import io
import logging
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional
from decimal import Decimal, ROUND_HALF_UP
from uuid import uuid4
import bcrypt
import pandas as pd
import stripe
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Flask, request, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import subprocess

# ============================
# APP
# ============================
app = Flask(__name__)

ENV = (os.getenv("FLASK_ENV") or "").strip().lower()
IS_PROD = ENV == "production"

# ============================
# LOGGING
# ============================
logging.basicConfig(
    level=logging.INFO if IS_PROD else logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ============================
# CONFIG
# ============================
app.config["DEBUG"] = False if IS_PROD else True

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise ValueError("SECRET_KEY es obligatorio (env var).")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
if not ADMIN_API_KEY:
    logger.warning("ADMIN_API_KEY no está configurado (no podrás usar endpoints /admin/*).")

# ============================
# DB CONFIG
# ============================
def _normalize_database_url(url: str) -> str:
    if url and url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url

db_url_env = _normalize_database_url(os.getenv("DATABASE_URL", ""))

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

app.config["SQLALCHEMY_DATABASE_URI"] = db_url_env or default_db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ============================
# PUBLIC URL (RAILWAY)
# ============================
PUBLIC_BASE_URL = os.getenv(
    "PUBLIC_BASE_URL",
    "https://flaskstripeserver-production.up.railway.app"
).rstrip("/")

SUCCESS_URL = os.getenv("SUCCESS_URL", f"{PUBLIC_BASE_URL}/success")
CANCEL_URL = os.getenv("CANCEL_URL", f"{PUBLIC_BASE_URL}/cancel")

# ============================
# STRIPE CONFIG (ENV)
# ============================
stripe.api_key = os.getenv("STRIPE_API_KEY", "")
webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")

if not stripe.api_key:
    logger.warning("STRIPE_API_KEY no está configurado. Stripe checkout NO funcionará.")
if not webhook_secret:
    logger.warning("STRIPE_WEBHOOK_SECRET no está configurado. Webhook NO funcionará.")
if not STRIPE_PRICE_ID:
    logger.warning("STRIPE_PRICE_ID no está configurado. No podrás crear checkout session.")

ALLOW_LEGACY_STRIPE = (os.getenv("ALLOW_LEGACY_STRIPE", "1").strip().lower() in ("1", "true", "yes"))

# ============================
# TRANSFER CONFIG (ENV)
# ============================
TRANSFER_BANK_NAME = os.getenv("TRANSFER_BANK_NAME", "").strip()
TRANSFER_BENEFICIARY_NAME = os.getenv("TRANSFER_BENEFICIARY_NAME", "").strip()
TRANSFER_CLABE = os.getenv("TRANSFER_CLABE", "").strip()
TRANSFER_AMOUNT_MXN = os.getenv("TRANSFER_AMOUNT_MXN", "").strip()  # ej "499.00"
TRANSFER_ORDER_TTL_MIN = int(os.getenv("TRANSFER_ORDER_TTL_MIN", "120"))  # minutos
TRANSFER_USE_UNIQUE_CENTS = (os.getenv("TRANSFER_USE_UNIQUE_CENTS", "1").strip().lower() in ("1", "true", "yes"))

def _transfer_enabled() -> bool:
    return all([TRANSFER_BANK_NAME, TRANSFER_BENEFICIARY_NAME, TRANSFER_CLABE, TRANSFER_AMOUNT_MXN])

# ============================
# OVERRIDES DE PRUEBAS (SOLO DEV)
# ============================
TEST_CLIENT_OVERRIDES = {"PECACAS": "jm"}  # solo aplica si NO es prod

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
# UTILS TIME (UTC)
# ============================
def utcnow() -> datetime:
    return datetime.utcnow()

# ============================
# MODELOS
# ============================

class Usuario(db.Model):
    __tablename__ = "usuarios"

    # asegúrate de que esto sea Integer si tu DB tiene usuarios_id_seq
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    client_id = db.Column(db.String(50), nullable=False)

    # Guardamos UTC naive (datetime.utcnow())
    license_expiration = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

    vins = db.relationship("VIN", backref="owner", lazy=True)

    # ✅ Opción A: re-agregar columnas existentes en DB
    last_year = db.Column(db.Integer, nullable=True)
    secuencial = db.Column(db.Integer, nullable=True)

User = Usuario

class VIN(db.Model):
    __tablename__ = "VIN"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    vin_completo = db.Column(db.String(17), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

class Subscription(db.Model):
    __tablename__ = "subscriptions"

    id = db.Column(db.Integer, primary_key=True)
    subscription_id = db.Column(db.String, unique=True, nullable=False)
    customer_id = db.Column(db.String)
    status = db.Column(db.String)
    current_period_end = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now())

class YearSequence(db.Model):
    __tablename__ = "year_sequences"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    secuencial = db.Column(db.Integer, default=1)

    __table_args__ = (db.UniqueConstraint("user_id", "year", name="uq_user_year"),)

class TransferOrder(db.Model):
    __tablename__ = "transfer_orders"

    # OJO: en la DB ES VARCHAR
    id = db.Column(db.String, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)

    # En la DB existe amount_mxn y currency
    amount_mxn = db.Column(db.Numeric, nullable=False)
    currency = db.Column(db.String, nullable=False)

    reference = db.Column(db.String(64), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    tracking_key = db.Column(db.String(128), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=True)

    submitted_at = db.Column(db.DateTime, nullable=True)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    validated_by = db.Column(db.String, nullable=True)
    validation_note = db.Column(db.String, nullable=True)
    cep_folio = db.Column(db.String, nullable=True)

    # La DB lo tiene como nullable
    amount_cents = db.Column(db.Integer, nullable=True)

    def to_public_dict(self):
        # Si amount_cents está, úsalo. Si no, calcúlalo desde amount_mxn
        if self.amount_cents is not None:
            amount_mxn_str = f"{self.amount_cents / 100:.2f}"
        else:
            amount_mxn_str = f"{Decimal(self.amount_mxn):.2f}"

        return {
            "order_id": self.id,
            "reference": self.reference,
            "status": self.status,
            "amount_mxn": amount_mxn_str,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "tracking_key": self.tracking_key,
        }

# IMPORTANTE:
# En producción NO usamos create_all. Migraciones mandan.
ALLOW_CREATE_ALL = (os.getenv("ALLOW_CREATE_ALL", "0").strip().lower() in ("1", "true", "yes"))
if (not IS_PROD) and ALLOW_CREATE_ALL:
    with app.app_context():
        try:
            db.create_all()
            logger.warning("db.create_all() ejecutado (DEV). En producción NO se debe usar.")
        except Exception as e:
            logger.warning(f"No se pudo db.create_all(): {e}")

# ============================
# AUTH (TOKEN)
# ============================
def _token_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="vinder-auth")

def create_auth_token(user: User) -> str:
    return _token_serializer().dumps({"uid": user.id})

def get_user_from_token(token: str, max_age_seconds: int = 60 * 60 * 24 * 7) -> Optional[User]:
    try:
        data = _token_serializer().loads(token, max_age=max_age_seconds)
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
        api_key = request.headers.get("X-Admin-Key", "")
        if not ADMIN_API_KEY or api_key != ADMIN_API_KEY:
            return jsonify({"error": "No autorizado"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ============================
# HELPERS
# ============================
def get_user_by_username(username: str) -> Optional[User]:
    return User.query.filter_by(username=username).first()

def license_is_active(user: User) -> bool:
    if not user or not user.license_expiration:
        return False
    return user.license_expiration > utcnow()

def _set_license_expiration_max(user: User, new_expiration_utc: datetime) -> bool:
    """Setea license_expiration al máximo entre el valor actual y new_expiration_utc (ambos UTC naive)."""
    if not user:
        return False
    now = utcnow()
    current = user.license_expiration
    if current and current > now:
        user.license_expiration = max(current, new_expiration_utc)
    else:
        user.license_expiration = new_expiration_utc
    db.session.commit()
    return True

def extend_license(user: User, days: int = 365) -> bool:
    if not user:
        return False
    now = utcnow()
    base = user.license_expiration if (user.license_expiration and user.license_expiration > now) else now
    user.license_expiration = base + timedelta(days=days)
    db.session.commit()
    return True

def _apply_test_client_override_if_needed(user: User) -> None:
    # SOLO fuera de producción
    if IS_PROD:
        return
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

def _parse_mxn_to_cents(s: str) -> int:
    d = Decimal(s).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int((d * 100).to_integral_value(rounding=ROUND_HALF_UP))

def _gen_reference(prefix: str = "VDR") -> str:
    alphabet = string.ascii_uppercase + string.digits
    rnd = "".join(secrets.choice(alphabet) for _ in range(10))
    return f"{prefix}-{rnd}"

def _expire_transfer_orders_now() -> None:
    try:
        now = utcnow()
        q = TransferOrder.query.filter(
            TransferOrder.status.in_(["pending", "submitted"]),
            TransferOrder.expires_at < now
        )
        updated = q.update({TransferOrder.status: "expired"}, synchronize_session=False)
        if updated:
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"No se pudo expirar órdenes: {e}")

def _choose_unique_cents(base_cents: int) -> int:
    if not TRANSFER_USE_UNIQUE_CENTS:
        return base_cents
    try:
        now = utcnow()
        live = TransferOrder.query.filter(
            TransferOrder.status.in_(["pending", "submitted"]),
            TransferOrder.expires_at > now,
            TransferOrder.amount_cents.between(base_cents, base_cents + 99),
        ).with_entities(TransferOrder.amount_cents).all()
        used = {row[0] - base_cents for row in live}
        candidates = [c for c in range(1, 100) if c not in used]
        if not candidates:
            return base_cents + secrets.randbelow(99) + 1
        return base_cents + secrets.choice(candidates)
    except Exception as e:
        logger.warning(f"No se pudo elegir centavos únicos: {e}")
        return base_cents + secrets.randbelow(99) + 1

def _transfer_public_info(amount_cents: int, reference: str):
    return {
        "method": "transfer",
        "bank_name": TRANSFER_BANK_NAME,
        "beneficiary_name": TRANSFER_BENEFICIARY_NAME,
        "clabe": TRANSFER_CLABE,
        "amount_mxn": f"{amount_cents / 100:.2f}",
        "reference": reference,
        "concept": reference,
        "ttl_minutes": TRANSFER_ORDER_TTL_MIN,
        "unique_cents": TRANSFER_USE_UNIQUE_CENTS,
    }

# ============================
# SECURITY HEADERS (simple)
# ============================
@app.after_request
def add_security_headers(resp):
    try:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # HSTS solo si realmente siempre va por HTTPS
        if IS_PROD:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    except Exception:
        pass
    return resp

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
        "server_time_utc": utcnow().isoformat(),
        "env": ENV or "unknown",
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

# ----------------------------
# Admin: usuarios / licencia
# ----------------------------
@app.route("/admin/create_user", methods=["POST"])
@require_admin
def admin_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    client_id = (data.get("client_id") or "").strip()

    if not username or not password:
        return jsonify({"error": "username y password son requeridos"}), 400

    # overrides solo fuera de prod
    if (not IS_PROD) and (not client_id) and username.upper() in TEST_CLIENT_OVERRIDES:
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

    return jsonify({"message": "Usuario creado", "username": new_user.username, "client_id": new_user.client_id}), 201

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

@app.route("/admin/renew_license", methods=["POST"])
@require_admin
def admin_renew_license():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username requerido"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    extend_license(user)
    return jsonify({
        "message": "Licencia renovada 1 año",
        "username": user.username,
        "license_expiration": user.license_expiration.isoformat()
    }), 200

# ----------------------------
# Licencia / VINs
# ----------------------------
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
        resultado = [
            {"vin_completo": v.vin_completo, "created_at": v.created_at.strftime("%Y-%m-%d %H:%M:%S")}
            for v in vins
        ]
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

# ----------------------------
# Stripe checkout (token + fallback legacy)
#  - Se setea metadata username para que el webhook pueda mapear usuario bien
# ----------------------------
@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    if not stripe.api_key or not STRIPE_PRICE_ID:
        return jsonify({"error": "Stripe no configurado en el servidor"}), 500

    auth = request.headers.get("Authorization", "")
    user: Optional[User] = None

    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1].strip()
        user = get_user_from_token(token)

    if user is None and ALLOW_LEGACY_STRIPE:
        data = request.get_json(silent=True) or {}
        legacy_username = (data.get("user") or "").strip()
        if legacy_username:
            user = get_user_by_username(legacy_username)
            if user:
                logger.warning("[LEGACY] create-checkout-session sin Authorization (usando user del body).")

    if user is None:
        return jsonify({"error": "Falta Authorization: Bearer <token>"}), 401

    try:
        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            mode="subscription",
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
            client_reference_id=user.username,  # útil, pero NO lo usamos como única fuente de verdad
            metadata={"username": user.username},
            subscription_data={"metadata": {"username": user.username}},
        )
        return jsonify({"url": session_obj.url}), 200
    except stripe.error.CardError as e:
        return jsonify({"error": e.user_message or "La tarjeta fue rechazada"}), 402
    except Exception as e:
        logger.error(f"Error al crear checkout session: {e}")
        return jsonify({"error": str(e)}), 500

def _username_from_stripe_object(obj: dict) -> str:
    # prefer metadata.username
    md = obj.get("metadata") or {}
    uname = (md.get("username") or "").strip()
    if uname:
        return uname
    # fallback (menos confiable): client_reference_id (solo en checkout.session)
    uname = (obj.get("client_reference_id") or "").strip()
    return uname

def _handle_subscription_paid(subscription_id: str) -> None:
    """
    Recupera la subscripción en Stripe, valida status y ajusta license_expiration a current_period_end (UTC).
    """
    if not subscription_id:
        return
    try:
        sub = stripe.Subscription.retrieve(subscription_id)
        status = (sub.get("status") or "").lower()
        if status not in ("active", "trialing"):
            logger.info(f"[STRIPE] subscription {subscription_id} status={status} (no renuevo licencia).")
            return

        uname = _username_from_stripe_object(sub)
        if not uname:
            logger.warning(f"[STRIPE] subscription {subscription_id} sin metadata.username (no puedo mapear usuario).")
            return

        user = get_user_by_username(uname)
        if not user:
            logger.warning(f"[STRIPE] usuario '{uname}' no existe en DB (subscription {subscription_id}).")
            return

        cpe = sub.get("current_period_end")
        if not cpe:
            logger.warning(f"[STRIPE] subscription {subscription_id} sin current_period_end.")
            return

        # Stripe entrega epoch seconds UTC
        new_exp = datetime.utcfromtimestamp(int(cpe))
        _set_license_expiration_max(user, new_exp)
        logger.info(f"[STRIPE] Licencia set hasta {new_exp.isoformat()} para user={uname} (sub={subscription_id}).")

    except Exception as e:
        logger.error(f"[STRIPE] Error procesando subscription {subscription_id}: {e}")

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    if not webhook_secret:
        return jsonify({"error": "Webhook no configurado"}), 500

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        event_type = event.get("type", "")
        obj = event.get("data", {}).get("object", {}) or {}

        # 1) Checkout terminado: si es subscription, intenta leer subscription_id
        if event_type == "checkout.session.completed":
            # OJO: session.completed puede disparar antes que invoice.paid en algunos flujos.
            subscription_id = (obj.get("subscription") or "").strip()
            if subscription_id:
                _handle_subscription_paid(subscription_id)
            else:
                # Si fuera pago único (no es tu caso ahora), podrías validar payment_status == "paid"
                pay_status = (obj.get("payment_status") or "").lower()
                uname = _username_from_stripe_object(obj)
                if pay_status == "paid" and uname:
                    u = get_user_by_username(uname)
                    if u:
                        extend_license(u, days=365)

        # 2) Señal fuerte: invoice pagada (recomendado para subscripciones)
        elif event_type == "invoice.paid":
            subscription_id = (obj.get("subscription") or "").strip()
            if subscription_id:
                _handle_subscription_paid(subscription_id)

        # 3) Opcional: cuando cambia subscripción
        elif event_type == "customer.subscription.updated":
            subscription_id = (obj.get("id") or "").strip()
            if subscription_id:
                _handle_subscription_paid(subscription_id)

        return jsonify({"status": "success"}), 200

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

# ----------------------------
# Transferencia (sin comisiones)
# ----------------------------
@app.route("/transfer/info", methods=["GET"])
@require_auth
def transfer_info():
    if not _transfer_enabled():
        return jsonify({"error": "Transferencia no configurada en el servidor"}), 500

    base_cents = _parse_mxn_to_cents(TRANSFER_AMOUNT_MXN)
    return jsonify({
        "enabled": True,
        "bank_name": TRANSFER_BANK_NAME,
        "beneficiary_name": TRANSFER_BENEFICIARY_NAME,
        "clabe": TRANSFER_CLABE,
        "base_amount_mxn": f"{base_cents/100:.2f}",
        "ttl_minutes": TRANSFER_ORDER_TTL_MIN,
        "unique_cents": TRANSFER_USE_UNIQUE_CENTS,
    }), 200

@app.route("/transfer/create-order", methods=["POST"])
@require_auth
def transfer_create_order():
    if not _transfer_enabled():
        return jsonify({"error": "Transferencia no configurada en el servidor"}), 500

    _expire_transfer_orders_now()

    user = request.current_user
    try:
        base_cents = _parse_mxn_to_cents(TRANSFER_AMOUNT_MXN)
        amount_cents = _choose_unique_cents(base_cents)
        reference = _gen_reference("VDR")
        expires_at = utcnow() + timedelta(minutes=TRANSFER_ORDER_TTL_MIN)

        order = TransferOrder(
            id=str(uuid4()),
            user_id=user.id,
            amount_cents=amount_cents,
            amount_mxn=Decimal(amount_cents) / Decimal(100),
            currency="MXN",
            reference=reference,
            status="pending",
            created_at=utcnow(),  # ✅ CLAVE
            expires_at=expires_at,
        )

        # Devuelve 200 para que cliente sea menos quisquilloso
        return jsonify({
            "order": order.to_public_dict(),
            "payment": _transfer_public_info(amount_cents=amount_cents, reference=reference),
            "notes": "Haz la transferencia con el CONCEPTO/REFERENCIA EXACTO. Después envía tu clave de rastreo.",
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creando orden transferencia: {e}")
        return jsonify({"error": "No se pudo crear la orden de transferencia"}), 500

@app.route("/transfer/my-orders", methods=["GET"])
@require_auth
def transfer_my_orders():
    _expire_transfer_orders_now()
    user = request.current_user
    orders = TransferOrder.query.filter_by(user_id=user.id).order_by(TransferOrder.created_at.desc()).limit(20).all()
    return jsonify({"orders": [o.to_public_dict() for o in orders]}), 200

@app.route("/transfer/submit", methods=["POST"])
@require_auth
def transfer_submit():
    _expire_transfer_orders_now()
    user = request.current_user
    data = request.get_json(silent=True) or {}

    reference = (data.get("reference") or "").strip()
    tracking_key = (data.get("tracking_key") or "").strip()

    if not reference or not tracking_key:
        return jsonify({"error": "reference y tracking_key son requeridos"}), 400

    order = TransferOrder.query.filter_by(user_id=user.id, reference=reference).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status in ("approved", "rejected", "expired"):
        return jsonify({"error": f"No puedes enviar comprobante. Estado actual: {order.status}"}), 400

    if order.expires_at < utcnow():
        order.status = "expired"
        db.session.commit()
        return jsonify({"error": "La orden expiró. Crea una nueva."}), 400

    order.tracking_key = tracking_key
    order.status = "submitted"
    db.session.commit()

    return jsonify({"message": "Comprobante enviado. En espera de aprobación.", "order": order.to_public_dict()}), 200

# ----------------------------
# Admin: aprobar/rechazar transferencias
# ----------------------------
@app.route("/admin/transfer/list", methods=["GET"])
@require_admin
def admin_transfer_list():
    _expire_transfer_orders_now()
    status = (request.args.get("status") or "").strip().lower()
    q = TransferOrder.query
    if status:
        q = q.filter_by(status=status)
    orders = q.order_by(TransferOrder.created_at.desc()).limit(200).all()
    return jsonify({"orders": [o.to_public_dict() for o in orders]}), 200

@app.route("/admin/transfer/approve", methods=["POST"])
@require_admin
def admin_transfer_approve():
    _expire_transfer_orders_now()
    data = request.get_json(silent=True) or {}
    reference = (data.get("reference") or "").strip()

    if not reference:
        return jsonify({"error": "reference es requerido"}), 400

    order = TransferOrder.query.filter_by(reference=reference).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status == "approved":
        return jsonify({"message": "Ya estaba aprobada", "order": order.to_public_dict()}), 200

    if order.status in ("rejected", "expired"):
        return jsonify({"error": f"No se puede aprobar. Estado: {order.status}"}), 400

    user = db.session.get(User, order.user_id)
    if not user:
        return jsonify({"error": "Usuario de la orden no existe"}), 500

    try:
        order.status = "approved"
        db.session.commit()

        extend_license(user, days=365)

        return jsonify({"message": "Orden aprobada y licencia renovada", "order": order.to_public_dict()}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error aprobando orden {reference}: {e}")
        return jsonify({"error": "No se pudo aprobar"}), 500

@app.route("/admin/transfer/reject", methods=["POST"])
@require_admin
def admin_transfer_reject():
    _expire_transfer_orders_now()
    data = request.get_json(silent=True) or {}
    reference = (data.get("reference") or "").strip()

    if not reference:
        return jsonify({"error": "reference es requerido"}), 400

    order = TransferOrder.query.filter_by(reference=reference).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status in ("approved", "expired"):
        return jsonify({"error": f"No se puede rechazar. Estado: {order.status}"}), 400

    order.status = "rejected"
    db.session.commit()
    return jsonify({"message": "Orden rechazada", "order": order.to_public_dict()}), 200

# ----------------------------
# Updates endpoint (si lo usas)
# ----------------------------
ENABLE_UPDATES_ENDPOINT = (os.getenv("ENABLE_UPDATES_ENDPOINT", "0").strip().lower() in ("1", "true", "yes"))

@app.route("/check_updates", methods=["GET"])
@require_admin
def check_updates():
    if not ENABLE_UPDATES_ENDPOINT:
        # No expongas esto en prod salvo que sepas exactamente por qué lo quieres.
        return jsonify({"error": "Endpoint deshabilitado"}), 404

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

# ============================
# MAIN (solo dev/local)
# ============================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Iniciando servidor en el puerto {port} (DEBUG={app.config['DEBUG']}, ENV={ENV})")
    app.run(host="0.0.0.0", port=port)
