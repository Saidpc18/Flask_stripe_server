import os
import io
import logging
from datetime import datetime, timedelta, timezone
import subprocess

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
    level=logging.INFO,  # pon DEBUG si quieres más detalle
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

# Fix común: postgres:// -> postgresql://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# ============================
# STRIPE
# ============================
stripe.api_key = os.getenv("STRIPE_API_KEY")
if not stripe.api_key:
    raise ValueError("Falta STRIPE_API_KEY (sk_test_... o sk_live_...)")

webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
if not webhook_secret:
    raise ValueError("Falta STRIPE_WEBHOOK_SECRET (whsec_...)")

def get_price_id() -> str:
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
        # si viene naive, asumimos UTC para no crashear
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
    license_expiration = db.Column(db.DateTime, nullable=True)  # puede ser naive
    secuencial = db.Column(db.Integer, default=0)
    last_year = db.Column(db.Integer, nullable=True)
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
# INIT DB (evita 500 por tablas faltantes)
# ============================
with app.app_context():
    try:
        db.create_all()
        db.session.execute(text("SELECT 1"))
        logger.info("DB ready (create_all + SELECT 1).")
    except Exception as e:
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
    # guardamos naive compatible (UTC sin tz) para evitar dramas con columnas sin tz
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
# ENDPOINT PROTEGIDO (ARREGLADO)
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
            {
                "vin_completo": vin.vin_completo,
                "created_at": vin.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
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

        data = [
            {"VIN": vin.vin_completo, "Fecha de Creación": vin.created_at.strftime("%Y-%m-%d %H:%M:%S")}
            for vin in user.vins
        ]
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
                logger.warning(f"El VIN {vin_str} tenía el código de año en pos 9 (idx 8). Se usará '{year_letter}'.")
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


# ============================
# TUFUP (solo si lo usas)
# ============================
@app.route("/check_updates", methods=["GET"])
def check_updates():
    def generate():
        try:
            yield "data: Configurando repositorio de actualizaciones...\n\n"
            subprocess.run(["tufup", "init"], check=True)
            yield "data: Repositorio configurado.\n\n"

            yield "data: Verificando actualizaciones...\n\n"
            result = subprocess.run(["tufup", "targets"], capture_output=True, text=True, check=True)
            stdout = result.stdout
            yield f"data: Resultado: {stdout}\n\n"

            if "New version available" in stdout:
                yield "data: Actualización disponible. Descarga la nueva versión desde la release.\n\n"
            else:
                yield "data: No hay actualizaciones disponibles.\n\n"
        except Exception as e:
            yield f"data: Error durante verificación: {e}\n\n"

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Iniciando servidor en puerto {port} (DEBUG={app.config['DEBUG']})")
    app.run(host="0.0.0.0", port=port)
