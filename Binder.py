import threading
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import webbrowser
import logging
import os
import sys
from datetime import datetime, timedelta
import stripe
import psycopg2

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
# CATÁLOGOS (LOCALES)
# ============================
posicion_4 = {
    "JM Remolque Cama Baja Tapada": "M",
    "JM Remolque Cama Baja Abierta": "L",
    "JM Remolque Cama Alta plataforma": "K",
    "JM Remolque Ganadero": "J",
    "JM Remolque VOLTEO Cama Baja": "H",
    "JM Remolque VOLTEO Cama Alta": "G",
    "JM Remolque Cuello Ganzo Ganadero": "F",
    "JM Remolque Cuello Ganzo Cama Baja": "E",
    "JM Remolque Cuello Ganzo Cama Alta": "D",
    "JM Semirremolque Tipo Gondola": "C",
    "JM Semirremolque Tipo Jaula Granelera": "B"
}
posicion_5 = {
    "5' X 10' A 14' Pies": "1",
    "5´ X 15´ A 20´Pies\t": "2",
    "6´ X 10´ A  14´ Pies": "3",
    "6´ X 15´ A  20´ Pies": "4",
    "7´ X 10´ A  15´  Pies": "5",
    "7´ X 16´ A 21´ Pies": "6",
    "7´ X 22´ A 27´ Pies": "7",
    "8´ X 16´ A  21´ Pies": "8",
    "8´ X 22´ A  27´ Pies": "9",
    "8.5´ X 16´ A  21´ Pies": "A",
    "8.5´ X 22´ A 27´ Pies": "B"
}
posicion_6 = {
    "1 Eje, Rin 13, 5 birlos, 800, Suspensión de balancin": "A",
    "1 Eje, Rin 15, 5 birlos, 1.500, Suspensión de balancin": "C",
    "1 Eje, Rin 16, 8 birlos, 3.000, Suspensión de balancin": "E",
    "2 Ejes, Rin 15, 5 birlos, 3.000, Suspensión de balancin": "F",
    "2 Ejes, Rin 15, 8 birlos, 6.000, Suspensión de balancin": "H",
    "2 Ejes, Rin 16, 8 birlos, 6.000, Suspensión de balancin": "K",
    "3 Ejes, Rin 16, 8 birlos, 9.000, Suspensión de balancin": "N",
    "2 Ejes, Rin 16, 8 birlos, Doble Rodada,10.000, Suspensión de balancin": "R",
    "2 Ejes, rin 22.5, 10 birlos, 30.000, Suspensión de aire": "S",
    "2 Ejes, rin 24.5, 10 birlos, 30.000, Suspensión de aire": "T",
    "3 Ejes, rin 24.5, 10 birlos, 40.000, Suspensión de aire": "U",
    "3 Ejes, rin 24.5, 24 m3, 30.000, Suspensión de aire": "V",
    "3 Ejes, rin 24.5, 30 m3, 45.000, Suspensión de aire": "Z"
}
posicion_7 = {
    "300 A  500": "9",
    "501 A 700": "8",
    "701 A 900": "7",
    "901 A 1100": "6",
    "1101 A 1300": "5",
    "1301 A 1500": "4",
    "1501 A 1700": "3",
    "1701 A 1900": "2",
    "1901 A 2100": "1",
    "2101 A 2300": "A"
}
posicion_8 = {
    "Sin Frenos": "9",
    "Frenos de disco": "8",
    "Frenos Electricos": "7",
    "Frenos de Aire": "6"
}
posicion_10 = {
    "2024": "R",
    "2025": "S",
    "2026": "T",
    "2027": "V",
    "2028": "W"
}
posicion_11 = {
    "Ex Hacienda la Honda, Zacatecas, México": "A"
}

# ============================
# CONFIGURACIÓN DE LA BASE DE DATOS (Flask + psycopg2)
# ============================
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "vindatabase"),
    "user": os.getenv("DB_USER", "vindatabase_owner"),
    "password": os.getenv("DB_PASSWORD", "kl8FIcyADWn4"),
    "host": os.getenv("DB_HOST", "ep-solitary-frost-a5hss4fj.us-east-2.aws.neon.tech"),
    "port": int(os.getenv("DB_PORT", 5432))
}

def conectar_bd():
    import psycopg2
    return psycopg2.connect(**DB_CONFIG)

# ============================
# FLASK - LÓGICA DE SERVIDOR
# ============================
from flask import Flask, request, jsonify
from marshmallow import Schema, fields, ValidationError

app = Flask(__name__)

# Configura DEBUG según la variable de entorno
if os.getenv("FLASK_ENV") == "production":
    app.config["DEBUG"] = False
else:
    app.config["DEBUG"] = True

import stripe

stripe.api_key = os.getenv(
    "STRIPE_API_KEY",
    "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"
)
webhook_secret = os.getenv(
    "STRIPE_WEBHOOK_SECRET",
    "whsec_4QAnSKkUNDYAoOSfmURtHNelKARrQw5k"
)

# ============================
# VALIDACIÓN DE EVENTOS STRIPE
# ============================
class StripeEventSchema(Schema):
    type = fields.String(required=True)
    data = fields.Dict(required=True)

# ============================
# FUNCIONES DE USUARIOS (psycopg2)
# ============================
def cargar_usuarios():
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT username, password, license_expiration, secuencial FROM usuarios;")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    usuarios = {}
    for row in rows:
        username, password, license_exp, secuencial = row
        if license_exp:
            license_str = license_exp.strftime("%Y-%m-%d")
        else:
            license_str = None
        usuarios[username] = {
            "password": password,
            "license_expiration": license_str,
            "secuencial": secuencial
        }
    return usuarios

from datetime import datetime, timedelta

def licencia_activa(usuario):
    todos = cargar_usuarios()
    if usuario not in todos:
        return False

    licencia = todos[usuario].get("license_expiration")
    if not licencia:
        return False

    return datetime.strptime(licencia, "%Y-%m-%d") > datetime.now()

def renovar_licencia(usuario):
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

def obtener_user_id(username):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT id FROM usuarios WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else None

def guardar_vin(username, vin_data):
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

@app.route("/")
def home():
    return "Bienvenido a la API de VIN Builder"

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
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403
    return jsonify({"message": "Acceso permitido a la función principal."})

@app.route("/guardar_vin", methods=["POST"])
def guardar_vin_endpoint():
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
    usuario = request.args.get("user")
    if not licencia_activa(usuario):
        return jsonify({"error": "Licencia expirada. Renueva para continuar usando la aplicación."}), 403

    vin_list = listar_vins(usuario)
    return jsonify({"vins": vin_list})

# ============================
# CLASE PRINCIPAL TKINTER
# ============================
class VINBuilderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("VIN Builder - con PostgreSQL")
        self.master.state("zoomed")  # Maximizar la ventana

        style = ttk.Style()
        style.theme_use("clam")

        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(fill="both", expand=True)

        # Variables de OptionMenu + WMI
        self.var_wmi = tk.StringVar(value="3J9")
        self.var_c4 = tk.StringVar()
        self.var_c5 = tk.StringVar()
        self.var_c6 = tk.StringVar()
        self.var_c7 = tk.StringVar()
        self.var_c8 = tk.StringVar()
        self.var_c10 = tk.StringVar()
        self.var_c11 = tk.StringVar()

        # Usuario actual
        self.usuario_actual = None
        self.result_label = None

        self.mostrar_ventana_inicio()

    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()

        lbl = ttk.Label(self.main_frame, text="Bienvenido a VIN Builder",
                        font=("Arial", 16, "bold"))
        lbl.pack(pady=20)

        ttk.Button(self.main_frame, text="Crear Cuenta",
                   command=self.ventana_crear_cuenta).pack(pady=5)
        ttk.Button(self.main_frame, text="Iniciar Sesión",
                   command=self.ventana_iniciar_sesion).pack(pady=5)

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()

        ttk.Label(self.main_frame, text="Crear Cuenta",
                  font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(self.main_frame, text="(Esta lógica se haría en el servidor Flask)").pack()

        ttk.Button(self.main_frame, text="Volver",
                   command=self.mostrar_ventana_inicio).pack(pady=10)

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()

        ttk.Label(self.main_frame, text="Iniciar Sesión",
                  font=("Arial", 14, "bold")).pack(pady=10)

        ttk.Label(self.main_frame, text="Usuario:").pack()
        entry_user = ttk.Entry(self.main_frame)
        entry_user.pack()

        ttk.Label(self.main_frame, text="Contraseña:").pack()
        entry_pass = ttk.Entry(self.main_frame, show="*")
        entry_pass.pack()

        def do_login():
            user = entry_user.get().strip()
            pw = entry_pass.get()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            # Por ahora, asumimos que cualquier usuario es válido
            messagebox.showinfo("Éxito", f"Bienvenido, {user}")
            self.usuario_actual = user
            self.ventana_principal()

        ttk.Button(self.main_frame, text="Iniciar Sesión",
                   command=do_login).pack(pady=10)
        ttk.Button(self.main_frame, text="Volver",
                   command=self.mostrar_ventana_inicio).pack()

    def ventana_principal(self):
        self.limpiar_main_frame()

        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="both", expand=True)
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True)

        titulo = ttk.Label(self.main_frame,
                           text=f"Hola, {self.usuario_actual}",
                           font=("Arial", 14, "bold"))
        titulo.pack(pady=10)

        ttk.Label(self.left_frame, text="Generar VIN",
                  font=("Arial", 12, "underline")).pack(pady=5)

        ttk.Label(self.left_frame, text="Código WMI:").pack()
        ttk.Entry(self.left_frame, textvariable=self.var_wmi).pack()

        self.crear_optionmenus(self.left_frame)

        ttk.Button(self.right_frame, text="Generar VIN",
                   command=self.generar_vin).pack(pady=10)

        self.result_label = ttk.Label(self.right_frame, text="VIN/NIV: ")
        self.result_label.pack(pady=5)

        ttk.Button(self.right_frame, text="Renovar Licencia",
                   command=self.iniciar_pago).pack(pady=10)

        ttk.Button(self.right_frame, text="Ver VINs Generados",
                   command=self.ventana_lista_vins).pack(pady=5)

        ttk.Button(self.right_frame, text="Cerrar Sesión",
                   command=self.cerrar_sesion).pack(pady=10)

    def crear_optionmenus(self, parent):
        ttk.Label(parent, text="Pos.4 (Ej. Modelo):").pack()
        self.menu_c4 = ttk.OptionMenu(
            parent,
            self.var_c4,
            self.valor_inicial(posicion_4),
            *posicion_4.keys()
        )
        self.menu_c4.pack()

        ttk.Label(parent, text="Pos.5:").pack()
        self.menu_c5 = ttk.OptionMenu(
            parent,
            self.var_c5,
            self.valor_inicial(posicion_5),
            *posicion_5.keys()
        )
        self.menu_c5.pack()

        ttk.Label(parent, text="Pos.6:").pack()
        self.menu_c6 = ttk.OptionMenu(
            parent,
            self.var_c6,
            self.valor_inicial(posicion_6),
            *posicion_6.keys()
        )
        self.menu_c6.pack()

        ttk.Label(parent, text="Pos.7:").pack()
        self.menu_c7 = ttk.OptionMenu(
            parent,
            self.var_c7,
            self.valor_inicial(posicion_7),
            *posicion_7.keys()
        )
        self.menu_c7.pack()

        ttk.Label(parent, text="Pos.8:").pack()
        self.menu_c8 = ttk.OptionMenu(
            parent,
            self.var_c8,
            self.valor_inicial(posicion_8),
            *posicion_8.keys()
        )
        self.menu_c8.pack()

        ttk.Label(parent, text="Pos.10:").pack()
        self.menu_c10 = ttk.OptionMenu(
            parent,
            self.var_c10,
            self.valor_inicial(posicion_10),
            *posicion_10.keys()
        )
        self.menu_c10.pack()

        ttk.Label(parent, text="Pos.11:").pack()
        self.menu_c11 = ttk.OptionMenu(
            parent,
            self.var_c11,
            self.valor_inicial(posicion_11),
            *posicion_11.keys()
        )
        self.menu_c11.pack()

    def valor_inicial(self, dic):
        if dic:
            return list(dic.keys())[0]
        return ""

    def generar_vin(self):
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        wmi = self.var_wmi.get().strip().upper()
        if not wmi:
            messagebox.showerror("Error", "El WMI no puede estar vacío.")
            return

        c4 = posicion_4.get(self.var_c4.get(), "")
        c5 = posicion_5.get(self.var_c5.get(), "")
        c6 = posicion_6.get(self.var_c6.get(), "")
        c7 = posicion_7.get(self.var_c7.get(), "")
        c8 = posicion_8.get(self.var_c8.get(), "")
        c10 = posicion_10.get(self.var_c10.get(), "")
        c11 = posicion_11.get(self.var_c11.get(), "")

        if not (c4 and c5 and c6 and c7 and c8 and c10 and c11):
            messagebox.showerror("Error", "Faltan datos en uno de los catálogos.")
            return

        from datetime import datetime
        sec = datetime.now().strftime("%H%M%S")

        vin_data = {
            "c4": c4,
            "c5": c5,
            "c6": c6,
            "c7": c7,
            "c8": c8,
            "c10": c10,
            "c11": c11,
            "secuencial": sec
        }
        self.guardar_vin_en_flask(vin_data)

    def guardar_vin_en_flask(self, vin_data):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        url = "https://flask-stripe-server.onrender.com/guardar_vin"
        payload = {
            "user": self.usuario_actual,
            "vin_data": vin_data
        }
        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "VIN guardado correctamente (en PostgreSQL).")
            else:
                data = resp.json()
                err = data.get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo guardar el VIN: {err}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor Flask: {e}")

    def ventana_lista_vins(self):
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        vins = self.ver_vins_en_flask()
        vins_window = tk.Toplevel(self.master)
        vins_window.title("VINs Generados")
        vins_window.geometry("500x400")

        canvas = tk.Canvas(vins_window)
        scrollbar = ttk.Scrollbar(vins_window, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        texto_vins = ""
        for vin in vins:
            texto_vins += f"VIN:\n"
            texto_vins += f"  - c4: {vin['c4']}, c5: {vin['c5']}, c6: {vin['c6']}, c7: {vin['c7']}\n"
            texto_vins += f"  - c8: {vin['c8']}, c10: {vin['c10']}, c11: {vin['c11']}\n"
            texto_vins += f"  - secuencial: {vin['secuencial']}\n"
            fecha_crea = vin.get("created_at", "")
            texto_vins += f"  - creado: {fecha_crea}\n"
            texto_vins += "-" * 40 + "\n"

        ttk.Label(scroll_frame, text=texto_vins, justify=tk.LEFT).pack(pady=10)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def ver_vins_en_flask(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return []
        url = "https://flask-stripe-server.onrender.com/ver_vins"
        try:
            resp = requests.get(url, params={"user": self.usuario_actual})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vins", [])
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo obtener la lista de VINs: {err}")
                return []
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor Flask: {e}")
            return []

    def iniciar_pago(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "Inicia sesión para realizar el pago.")
            return
        try:
            server_url = "https://flask-stripe-server.onrender.com/create-checkout-session"
            response = requests.post(server_url, json={"user": self.usuario_actual})
            if response.status_code == 200:
                data = response.json()
                if "url" in data:
                    webbrowser.open(data["url"])
                    messagebox.showinfo("Pago Iniciado",
                                        "Se ha abierto la página de pago en tu navegador.")
                else:
                    messagebox.showerror("Error", "No se recibió una URL válida del servidor.")
            else:
                error_msg = response.json().get("error", "Error desconocido")
                messagebox.showerror("Error",
                                     f"No se pudo iniciar el proceso de pago: {error_msg}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error inesperado: {e}")

    def verificar_licencia(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return False
        try:
            response = requests.get(
                "https://flask-stripe-server.onrender.com/funcion-principal",
                params={"user": self.usuario_actual}
            )
            data = response.json()
            if response.status_code == 403:
                messagebox.showerror("Suscripción requerida", data["error"])
                return False
            elif "error" in data:
                messagebox.showerror("Suscripción requerida", data["error"])
                return False
            return True
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"No se pudo verificar la licencia: {e}")
            return False
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al verificar la licencia: {e}")
            return False

    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.mostrar_ventana_inicio()

# ============================
# INICIAR FLASK EN SEGUNDO PLANO Y TKINTER
# ============================
def run_flask():
    import traceback
    try:
        logger.info("Iniciando servidor Flask en puerto 5000")
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

    except Exception as e:
        logger.error(f"Error al iniciar Flask: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    # Inicia Flask en un hilo
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Inicia la interfaz gráfica
    root = tk.Tk()
    VINBuilderApp(root)
    root.mainloop()
