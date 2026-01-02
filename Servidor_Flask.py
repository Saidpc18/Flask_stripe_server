import os
import io
import logging
from datetime import datetime, timedelta, timezone
import subprocess
from decimal import Decimal
import secrets
import uuid

import bcrypt
import pandas as pd
import stripe

from flask import Flask, request, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import text


# ============================
# VERSION (para validar deploy)
# ============================
CODE_VERSION = os.getenv("CODE_VERSION", "railway-2025-12-31-01")
print("CODE_VERSION:", CODE_VERSION)
print("RUNNING FILE:", __file__)


# ============================
# LOGGING
# ============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ============================
# APP + PROXY FIX (Railway)
# ============================
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["DEBUG"] = False if os.getenv("FLASK_ENV") == "production" else True


# ============================
# BASE DE DATOS (Railway)
# ============================
db_url = os.getenv("DATABASE_URL")
if not db_url:
    raise ValueError("DATABASE_URL no está configurado (Railway la provee automáticamente)")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# ============================
# STRIPE (opcional)
# ============================
STRIPE_ENABLED = bool((os.getenv("STRIPE_API_KEY") or "").strip())
stripe.api_key = os.getenv("STRIPE_API_KEY") if STRIPE_ENABLED else None
webhook_secret = (os.getenv("STRIPE_WEBHOOK_SECRET") or "").strip() if STRIPE_ENABLED else ""

if STRIPE_ENABLED and not webhook_secret:
    logger.warning("STRIPE está habilitado pero falta STRIPE_WEBHOOK_SECRET (whsec_...). El webhook fallará.")

def get_price_id() -> str:
    if not STRIPE_ENABLED:
        return ""
    mode = "test" if (stripe.api_key or "").startswith("sk_test_") else "live"
    if mode == "test":
        return os.getenv("STRIPE_PRICE_ID_TEST") or os.getenv("STRIPE_PRICE_ID") or ""
    return os.getenv("STRIPE_PRICE_ID_LIVE") or os.getenv("STRIPE_PRICE_ID") or ""


# ============================
# UTILIDADES FECHAS (timezone-safe)
# ============================
def utc_now():
    return datetime.now(timezone.utc)

def to_utc_aware(dt: datetime | None):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ============================
# DICCIONARIO DE LETRAS → AÑO
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
    license_expiration = db.Column(db.DateTime, nullable=True)  # naive ok
    secuencial = db.Column(db.Integer, default=0)
    last_year = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.now())

    vins = db.relationship("VIN", backref="owner", lazy=True)


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

    id = db.Column(db.String(36), primary_key=True)  # UUID
    user_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=False)

    amount_mxn = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default="MXN", nullable=False)

    reference = db.Column(db.String(32), unique=True, nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)
    # pending | submitted | confirmed | rejected | expired

    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)

    tracking_key = db.Column(db.String(64), nullable=True)
    submitted_at = db.Column(db.DateTime, nullable=True)
    confirmed_at = db.Column(db.DateTime, nullable=True)

    # evidencia (manual CEP)
    validated_by = db.Column(db.String(50), nullable=True)
    validation_note = db.Column(db.String(400), nullable=True)
    cep_folio = db.Column(db.String(64), nullable=True)


# ============================
# INIT DB + PATCH ESQUEMA
# ============================
with app.app_context():
    try:
        db.create_all()
        db.session.execute(text("SELECT 1"))

        # Patch seguro (si ya existe transfer_orders sin estas columnas)
        db.session.execute(text("""
            ALTER TABLE transfer_orders
              ADD COLUMN IF NOT EXISTS validated_by varchar(50),
              ADD COLUMN IF NOT EXISTS validation_note varchar(400),
              ADD COLUMN IF NOT EXISTS cep_folio varchar(64);
        """))
        db.session.commit()

        logger.info("DB ready (create_all + schema patch + SELECT 1).")
    except Exception as e:
        db.session.rollback()
        logger.exception(f"DB init failed: {e}")


# ============================
# HELPERS
# ============================
def get_user_by_username(username: str):
    return User.query.filter_by(username=username).first()

def license_is_active(user: User) -> bool:
    if not user or not user.license_expiration:
        return False
    exp = to_utc_aware(user.license_expiration)
    return exp is not None and exp > utc_now()

def renew_license(user: User) -> bool:
    if not user:
        return False
    new_exp = utc_now() + timedelta(days=365)
    user.license_expiration = new_exp.replace(tzinfo=None)
    db.session.commit()
    return True

def obtener_o_incrementar_secuencial(username: str, year_input) -> int:
    user = get_user_by_username(username)
    if not user:
        logger.warning(f"Usuario {username} no existe.")
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


# ========= TRANSFERENCIA DIRECTA (ADMIN + CONFIG) =========
def require_admin(req) -> bool:
    expected = (os.getenv("ADMIN_TOKEN") or "").strip()
    if not expected:
        return False
    token = (req.headers.get("Authorization") or "").strip()
    return token == f"Bearer {expected}"

def make_transfer_reference(username: str) -> str:
    prefix = (username[:6] or "USER").upper()
    rand = secrets.token_hex(3).upper()
    return f"VND-{prefix}-{rand}"

def get_transfer_config():
    clabe = (os.getenv("TRANSFER_CLABE") or "").strip()
    beneficiary = (os.getenv("TRANSFER_BENEFICIARY_NAME") or "").strip()
    bank = (os.getenv("TRANSFER_BANK_NAME") or "").strip()
    amount_str = (os.getenv("TRANSFER_AMOUNT_MXN") or "").strip()
    ttl_min = int(os.getenv("TRANSFER_ORDER_TTL_MIN", "1440"))
    use_unique_cents = (os.getenv("TRANSFER_USE_UNIQUE_CENTS", "true").strip().lower() in ("1", "true", "yes"))

    if not (clabe and beneficiary and bank and amount_str):
        raise ValueError("Faltan variables TRANSFER_* (CLABE, BENEFICIARY_NAME, BANK_NAME, AMOUNT_MXN)")
    return clabe, beneficiary, bank, Decimal(amount_str), ttl_min, use_unique_cents


# ============================
# RUTAS BASE
# ============================
@app.get("/")
def home():
    return "Bienvenido a la API de Vinder (Railway-only)"

@app.get("/version")
def version():
    return {"code_version": CODE_VERSION}

@app.get("/health")
def health():
    return {"status": "ok", "code_version": CODE_VERSION}

@app.get("/db-test")
def db_test():
    try:
        db.session.execute(text("SELECT 1"))
        return {"ok": True}, 200
    except Exception as e:
        logger.exception(f"DB TEST FAILED: {e}")
        return {"ok": False, "error": str(e)}, 500


# ============================
# AUTH
# ============================
@app.route("/register", methods=["POST"])
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

    try:
        existing = get_user_by_username(username)
        if existing:
            return jsonify({"error": "El usuario ya existe."}), 400

        salt = bcrypt.gensalt()
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuario registrado exitosamente."}), 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error al registrar el usuario: {e}")
        return jsonify({"error": "Error al registrar el usuario"}), 500


@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña son requeridos"}), 400

    try:
        user = get_user_by_username(username)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
            return jsonify({"message": "Login exitoso"}), 200

        return jsonify({"error": "Contraseña incorrecta"}), 401
    except Exception as e:
        logger.exception(f"Error en login: {e}")
        return jsonify({"error": "Error interno"}), 500


# ============================
# SECUENCIAL
# ============================
@app.route("/obtener_secuencial", methods=["POST"])
def obtener_secuencial():
    data = request.json or {}
    username = data.get("user")
    year_value = data.get("year")

    if not username or not year_value:
        return jsonify({"error": "Se requiere 'user' y 'year'"}), 400

    try:
        nuevo_secuencial = obtener_o_incrementar_secuencial(username, year_value)
        return jsonify({"secuencial": nuevo_secuencial}), 200
    except Exception as e:
        logger.exception(f"Error al obtener secuencial: {e}")
        return jsonify({"error": "Error al obtener el secuencial"}), 500


# ============================
# STRIPE WEBHOOK
# ============================
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    if not STRIPE_ENABLED:
        return jsonify({"error": "Stripe disabled"}), 503
    if not webhook_secret:
        return jsonify({"error": "Stripe webhook secret missing"}), 500

    payload = request.get_data(cache=False)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        event_type = event.get("type", "")
        event_data = event.get("data", {}).get("object", {})

        logger.info(f"Evento recibido: {event_type}")

        if event_type == "checkout.session.completed":
            usuario = event_data.get("client_reference_id")
            if usuario:
                user = get_user_by_username(usuario)
                if renew_license(user):
                    logger.info(f"Licencia renovada para el usuario: {usuario}")
                else:
                    logger.warning(f"Usuario no encontrado: {usuario}")
            else:
                logger.warning("No llegó client_reference_id en la sesión.")

        return jsonify({"status": "success"}), 200

    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Firma inválida del webhook: {e}")
        return jsonify({"error": "Firma del webhook inválida"}), 400
    except Exception as e:
        logger.exception(f"Error procesando webhook: {e}")
        return jsonify({"error": "Error al procesar el webhook"}), 400


# ============================
# STRIPE CHECKOUT
# ============================
@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    if not STRIPE_ENABLED:
        return jsonify({"error": "Stripe disabled"}), 503

    try:
        data = request.json or {}
        user = data.get("user") or data.get("username")
        if not user:
            return jsonify({"error": "Se requiere 'user' o 'username'"}), 400

        price_id = get_price_id()
        if not price_id:
            return jsonify({"error": "Falta STRIPE_PRICE_ID (o *_TEST/*_LIVE)"}), 500

        checkout_mode = os.getenv("STRIPE_CHECKOUT_MODE", "subscription")  # subscription | payment

        public_base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
        base = public_base if public_base else request.host_url.rstrip("/")

        success_url = os.getenv("SUCCESS_URL", f"{base}/success")
        cancel_url = os.getenv("CANCEL_URL", f"{base}/cancel")

        logger.info(f"[checkout] user={user} price_id={price_id} mode={checkout_mode}")

        session_obj = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode=checkout_mode,
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=user,
        )

        return jsonify({"url": session_obj.url})
    except Exception as e:
        logger.exception(f"Error al crear la sesión de pago: {e}")
        return jsonify({"error": "Stripe error"}), 500


@app.route("/success", methods=["GET"])
def success():
    return "¡Pago exitoso! Gracias por tu compra."

@app.route("/cancel", methods=["GET"])
def cancel():
    return "El proceso de pago ha sido cancelado o ha fallado."


# ============================
# DIAGNOSTICO DB
# ============================
@app.get("/db-regclass")
def db_regclass():
    row = db.session.execute(text("""
        SELECT
            to_regclass('public.usuarios') AS usuarios,
            to_regclass('public.year_sequences') AS year_sequences,
            to_regclass('public.subscriptions') AS subscriptions,
            to_regclass('public.transfer_orders') AS transfer_orders
    """)).mappings().first()
    return dict(row), 200


# ============================
# LICENSE STATUS
# ============================
@app.get("/license-status")
def license_status():
    username = request.args.get("user")
    if not username:
        return jsonify({"error": "Falta ?user=..."}), 400

    try:
        user = get_user_by_username(username)
        if not user:
            return jsonify({"user": username, "exists": False, "active": False}), 404

        exp_raw = user.license_expiration
        exp_utc = to_utc_aware(exp_raw) if exp_raw else None
        now = utc_now()

        active = bool(exp_utc and exp_utc > now)

        return jsonify({
            "user": username,
            "exists": True,
            "active": active,
            "license_expiration_raw": exp_raw.isoformat() if exp_raw else None,
            "license_expiration_utc": exp_utc.isoformat() if exp_utc else None,
            "now_utc": now.isoformat(),
            "seconds_remaining": int((exp_utc - now).total_seconds()) if exp_utc else None
        }), 200

    except Exception as e:
        logger.exception(f"Error en /license-status para {username}: {e}")
        return jsonify({"error": "Error consultando la base de datos", "detail": str(e)}), 500


# ============================
# ENDPOINT PROTEGIDO
# ============================
@app.route("/funcion-principal", methods=["GET"])
def funcion_principal():
    usuario = request.args.get("user")
    if not usuario:
        return jsonify({"error": "Falta ?user=..."}), 400

    try:
        user = get_user_by_username(usuario)
    except Exception as e:
        logger.exception(f"DB error buscando usuario {usuario}: {e}")
        return jsonify({"error": "Error consultando la base de datos"}), 500

    if not license_is_active(user):
        return jsonify({"error": "Licencia expirada o usuario inexistente. Renueva para continuar."}), 403

    return jsonify({"message": "Acceso permitido a la función principal."}), 200


# ============================
# TRANSFERENCIA DIRECTA (SPEI)
# ============================
@app.post("/create-transfer-order")
def create_transfer_order():
    data = request.json or {}
    username = data.get("user") or data.get("username")
    if not username:
        return jsonify({"error": "Se requiere 'user'"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "Usuario no existe"}), 404

    try:
        clabe, beneficiary, bank, base_amount, ttl_min, use_unique_cents = get_transfer_config()
    except Exception as e:
        logger.exception(f"Transfer config error: {e}")
        return jsonify({"error": "Transfer config error"}), 500

    # Centavos únicos (ayuda conciliación manual)
    amount = base_amount
    if use_unique_cents:
        cents = Decimal(secrets.randbelow(99) + 1) / Decimal(100)
        amount = (base_amount + cents).quantize(Decimal("0.01"))
    else:
        amount = base_amount.quantize(Decimal("0.01"))

    # referencia única
    ref = None
    for _ in range(10):
        candidate = make_transfer_reference(username)
        if not TransferOrder.query.filter_by(reference=candidate).first():
            ref = candidate
            break
    if not ref:
        return jsonify({"error": "No se pudo generar referencia única"}), 500

    order_id = str(uuid.uuid4())
    expires_at = (utc_now() + timedelta(minutes=ttl_min)).replace(tzinfo=None)

    order = TransferOrder(
        id=order_id,
        user_id=user.id,
        amount_mxn=amount,
        currency="MXN",
        reference=ref,
        status="pending",
        expires_at=expires_at,
    )
    db.session.add(order)
    db.session.commit()

    return jsonify({
        "order_id": order_id,
        "user": username,
        "amount_mxn": str(amount),
        "currency": "MXN",
        "reference": ref,
        "beneficiary_name": beneficiary,
        "bank_name": bank,
        "clabe": clabe,
        "expires_at": expires_at.isoformat(),
        "instructions": [
            "Haz una transferencia SPEI por el monto exacto.",
            "En 'Concepto' o 'Referencia' escribe EXACTAMENTE la referencia.",
            "Luego envía tu clave de rastreo con /transfer-submit.",
            "No aceptamos capturas: se valida manualmente en CEP (Banxico)."
        ]
    }), 201


@app.get("/transfer-status")
def transfer_status():
    order_id = request.args.get("order_id")
    if not order_id:
        return jsonify({"error": "Falta ?order_id=..."}), 400

    order = TransferOrder.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    # expirar automáticamente
    if order.status in ("pending", "submitted") and order.expires_at:
        if order.expires_at < utc_now().replace(tzinfo=None):
            order.status = "expired"
            db.session.commit()

    return jsonify({
        "order_id": order.id,
        "status": order.status,
        "amount_mxn": str(order.amount_mxn),
        "reference": order.reference,
        "tracking_key": order.tracking_key,
        "created_at": order.created_at.isoformat() if order.created_at else None,
        "expires_at": order.expires_at.isoformat() if order.expires_at else None,
        "submitted_at": order.submitted_at.isoformat() if order.submitted_at else None,
        "confirmed_at": order.confirmed_at.isoformat() if order.confirmed_at else None,
        "cep_folio": order.cep_folio,
        "validated_by": order.validated_by,
        "validation_note": order.validation_note
    }), 200


@app.post("/transfer-submit")
def transfer_submit():
    data = request.json or {}
    order_id = data.get("order_id")
    tracking_key = (data.get("tracking_key") or "").strip()

    if not order_id or not tracking_key:
        return jsonify({"error": "Se requiere 'order_id' y 'tracking_key'"}), 400

    order = TransferOrder.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status in ("confirmed", "rejected", "expired"):
        return jsonify({"error": f"Orden en estado '{order.status}'"}), 400

    # expirar si ya pasó
    if order.expires_at and order.expires_at < utc_now().replace(tzinfo=None):
        order.status = "expired"
        db.session.commit()
        return jsonify({"error": "Orden expirada"}), 400

    order.tracking_key = tracking_key
    order.submitted_at = utc_now().replace(tzinfo=None)
    order.status = "submitted"
    db.session.commit()

    return jsonify({
        "message": "Recibido. Se validará manualmente en CEP y se activará la licencia al confirmarse.",
        "order_id": order_id,
        "status": order.status
    }), 200


# ============================
# ADMIN: CONFIRMAR / RECHAZAR
# ============================
@app.post("/admin/confirm-transfer")
def admin_confirm_transfer():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    order_id = data.get("order_id")
    cep_folio = (data.get("cep_folio") or "").strip()
    note = (data.get("note") or "").strip()
    admin_name = (data.get("validated_by") or "admin").strip()

    if not order_id:
        return jsonify({"error": "Se requiere 'order_id'"}), 400

    order = TransferOrder.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status == "confirmed":
        return jsonify({"message": "Ya estaba confirmada", "order_id": order_id}), 200

    if order.status == "expired":
        return jsonify({"error": "Orden expirada"}), 400

    # ✅ seguridad: solo confirmar si ya fue submitted
    if order.status != "submitted":
        return jsonify({"error": f"La orden debe estar en 'submitted'. Estado actual: {order.status}"}), 400

    # ✅ fuerza tracking_key (usuario tuvo que hacer /transfer-submit)
    if not order.tracking_key:
        return jsonify({"error": "La orden no tiene tracking_key. Usa /transfer-submit primero."}), 400

    # ✅ evidencia mínima (manual CEP)
    if not cep_folio:
        return jsonify({"error": "Falta 'cep_folio' (captura el folio/identificador del CEP)."}), 400

    user = User.query.filter_by(id=order.user_id).first()
    if not user:
        return jsonify({"error": "Usuario asociado no existe"}), 500

    renew_license(user)

    order.status = "confirmed"
    order.confirmed_at = utc_now().replace(tzinfo=None)
    order.cep_folio = cep_folio
    order.validation_note = note[:400] if note else None
    order.validated_by = admin_name[:50]
    db.session.commit()

    return jsonify({
        "message": "Transferencia confirmada. Licencia activada.",
        "order_id": order.id,
        "user": user.username,
        "amount_mxn": str(order.amount_mxn),
        "reference": order.reference,
        "tracking_key": order.tracking_key,
        "cep_folio": order.cep_folio,
        "license_expiration": user.license_expiration.isoformat() if user.license_expiration else None
    }), 200


@app.post("/admin/reject-transfer")
def admin_reject_transfer():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    order_id = data.get("order_id")
    reason = (data.get("reason") or "").strip()

    if not order_id:
        return jsonify({"error": "Se requiere 'order_id'"}), 400

    order = TransferOrder.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    if order.status in ("confirmed", "expired"):
        return jsonify({"error": f"No se puede rechazar en estado {order.status}"}), 400

    order.status = "rejected"
    order.validation_note = (reason[:400] if reason else "Rechazado por admin (CEP no coincide)")
    order.validated_by = "admin"
    db.session.commit()

    return jsonify({"message": "Orden rechazada", "order_id": order_id, "status": order.status}), 200


@app.get("/admin/transfer-orders")
def admin_transfer_orders():
    if not require_admin(request):
        return jsonify({"error": "Unauthorized"}), 401

    status = (request.args.get("status") or "").strip()
    q = TransferOrder.query
    if status:
        q = q.filter_by(status=status)

    orders = q.order_by(TransferOrder.created_at.desc()).limit(200).all()
    return jsonify({
        "count": len(orders),
        "orders": [{
            "order_id": o.id,
            "status": o.status,
            "amount_mxn": str(o.amount_mxn),
            "reference": o.reference,
            "tracking_key": o.tracking_key,
            "created_at": o.created_at.isoformat() if o.created_at else None,
            "expires_at": o.expires_at.isoformat() if o.expires_at else None,
            "submitted_at": o.submitted_at.isoformat() if o.submitted_at else None,
            "confirmed_at": o.confirmed_at.isoformat() if o.confirmed_at else None,
            "cep_folio": o.cep_folio,
            "validated_by": o.validated_by,
            "validation_note": o.validation_note
        } for o in orders]
    }), 200


# ============================
# VINS
# ============================
@app.route("/guardar_vin", methods=["POST"])
def guardar_vin_endpoint():
    data = request.json or {}
    user_name = data.get("user")
    vin_completo = data.get("vin_completo")

    if not user_name or not vin_completo:
        return jsonify({"error": "Faltan datos necesarios (user, vin_completo)"}), 400

    try:
        user = get_user_by_username(user_name)
        if not user:
            return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

        nuevo_vin = VIN(user_id=user.id, vin_completo=vin_completo)
        db.session.add(nuevo_vin)
        db.session.commit()
        return jsonify({"message": "VIN guardado exitosamente"}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error al guardar VIN: {e}")
        return jsonify({"error": "Error al guardar VIN"}), 500


@app.get("/transfer-instructions")
def transfer_instructions():
    order_id = request.args.get("order_id")
    username = request.args.get("user")

    if not order_id or not username:
        return jsonify({"error": "Falta ?order_id=...&user=..."}), 400

    order = TransferOrder.query.filter_by(id=order_id).first()
    if not order:
        return jsonify({"error": "Orden no encontrada"}), 404

    user = get_user_by_username(username)
    if not user or user.id != order.user_id:
        return jsonify({"error": "Orden no encontrada"}), 404

    # Auto-expirar si ya pasó el TTL
    if order.status in ("pending", "submitted") and order.expires_at:
        if order.expires_at < utc_now().replace(tzinfo=None):
            order.status = "expired"
            db.session.commit()

    try:
        clabe, beneficiary, bank, _, _, _ = get_transfer_config()
    except Exception as e:
        logger.exception(f"Transfer config error: {e}")
        return jsonify({"error": "Transfer config error"}), 500

    if order.status == "pending":
        instructions = [
            "Haz una transferencia SPEI por el monto exacto.",
            "En 'Concepto' o 'Referencia' escribe EXACTAMENTE la referencia.",
            "Luego envía tu clave de rastreo con /transfer-submit.",
            "No aceptamos capturas: se valida manualmente en CEP (Banxico)."
        ]
    elif order.status == "submitted":
        instructions = [
            "Ya recibimos tu clave de rastreo.",
            "Estamos validando manualmente en CEP (Banxico).",
            "Si en 24h no cambia a confirmado, contacta soporte con tu order_id."
        ]
    elif order.status == "confirmed":
        instructions = [
            "Pago confirmado.",
            "Tu licencia ya está activa. Puedes usar la app normalmente."
        ]
    elif order.status == "expired":
        instructions = [
            "Esta orden expiró.",
            "Genera una nueva orden de transferencia para obtener un nuevo monto y referencia."
        ]
    else:  # rejected u otros
        instructions = [
            "Esta orden fue rechazada.",
            "Genera una nueva orden o contacta soporte con tu order_id."
        ]

    resp = {
        "order_id": order.id,
        "user": username,
        "status": order.status,
        "amount_mxn": str(order.amount_mxn),
        "currency": order.currency,
        "reference": order.reference,
        "beneficiary_name": beneficiary,
        "bank_name": bank,
        "clabe": clabe,
        "expires_at": order.expires_at.isoformat() if order.expires_at else None,
        "instructions": instructions
    }

    # datos extra útiles cuando ya hubo submit/confirm
    if order.tracking_key:
        resp["tracking_key"] = order.tracking_key
    if order.cep_folio:
        resp["cep_folio"] = order.cep_folio

    return jsonify(resp), 200


@app.route("/ver_vins", methods=["GET"])
def ver_vins():
    user_name = request.args.get("user")
    if not user_name:
        return jsonify({"error": "Usuario no especificado"}), 400

    try:
        user = get_user_by_username(user_name)
        if not user:
            return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

        vins = user.vins
        resultado = [
            {"vin_completo": vin.vin_completo, "created_at": vin.created_at.strftime("%Y-%m-%d %H:%M:%S")}
            for vin in vins
        ]
        return jsonify({"vins": resultado}), 200
    except Exception as e:
        logger.exception(f"Error al listar VINs: {e}")
        return jsonify({"error": "Error al listar VINs"}), 500


@app.route("/export_vins", methods=["GET"])
def export_vins():
    user_name = request.args.get("user")
    if not user_name:
        return jsonify({"error": "Se requiere el parámetro 'user'"}), 400

    try:
        user = get_user_by_username(user_name)
        if not user:
            return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

        data = [{"VIN": vin.vin_completo, "Fecha de Creación": vin.created_at.strftime("%Y-%m-%d %H:%M:%S")}
                for vin in user.vins]
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
        logger.exception(f"Error al exportar VINs: {e}")
        return jsonify({"error": "Error al exportar VINs"}), 500


@app.route("/eliminar_todos_vins", methods=["POST"])
def eliminar_todos_vins():
    data = request.json or {}
    user_name = data.get("user")
    if not user_name:
        return jsonify({"error": "Se requiere el usuario."}), 400

    try:
        user = get_user_by_username(user_name)
        if not user:
            return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

        VIN.query.filter_by(user_id=user.id).delete()
        YearSequence.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({"message": "Todos los VINs han sido eliminados y el secuencial se ha reiniciado."}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error al eliminar todos los VINs: {e}")
        return jsonify({"error": "Error al eliminar VINs"}), 500


@app.route("/eliminar_ultimo_vin", methods=["POST"])
def eliminar_ultimo_vin():
    data = request.json or {}
    user_name = data.get("user")
    if not user_name:
        return jsonify({"error": "Se requiere el usuario."}), 400

    try:
        user = get_user_by_username(user_name)
        if not user:
            return jsonify({"error": f"Usuario '{user_name}' no existe"}), 404

        ultimo_vin = VIN.query.filter_by(user_id=user.id).order_by(VIN.created_at.desc()).first()
        if not ultimo_vin:
            return jsonify({"error": "No hay VINs para eliminar."}), 404

        vin_str = ultimo_vin.vin_completo
        if len(vin_str) < 10:
            return jsonify({"error": "El VIN almacenado no tiene el formato esperado."}), 500

        year_letter = vin_str[9]
        if year_letter not in YEAR_MAP:
            if len(vin_str) > 8 and vin_str[8] in YEAR_MAP:
                year_letter = vin_str[8]
            else:
                return jsonify({"error": "El VIN no contiene un código de año válido."}), 500

        year_int = YEAR_MAP[year_letter]
        year_seq = YearSequence.query.filter_by(user_id=user.id, year=year_int).first()
        if year_seq and year_seq.secuencial > 1:
            year_seq.secuencial -= 1
            db.session.commit()

        db.session.delete(ultimo_vin)
        db.session.commit()
        return jsonify({"message": "El último VIN ha sido eliminado y el secuencial se ha actualizado."}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error al eliminar el último VIN: {e}")
        return jsonify({"error": "Error al eliminar el último VIN"}), 500



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Iniciando servidor en puerto {port} (DEBUG={app.config['DEBUG']})")
    app.run(host="0.0.0.0", port=port)
