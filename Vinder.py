import os
import sys
import io
import json
import logging
import subprocess
import threading
import time
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

import requests
import webbrowser
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import pandas as pd
from PIL import Image, ImageTk


# ============================
# LOGGING
# ============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


# ============================
# CONFIG SERVER (RAILWAY-ONLY)
# ============================
SERVER_BASE = os.getenv("VINDER_SERVER_URL", "https://flaskstripeserver-production.up.railway.app").rstrip("/")
HTTP_TIMEOUT = (5, 30)  # (connect, read)


def api_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{SERVER_BASE}{path}"


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


# ============================
# PERSISTENCIA LOCAL (state)
# ============================
STATE_PATH = os.path.join(os.path.expanduser("~"), ".vinder_state.json")


def load_state() -> dict:
    try:
        if os.path.exists(STATE_PATH):
            with open(STATE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"No se pudo leer state: {e}")
    return {}


def save_state(state: dict) -> None:
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"No se pudo guardar state: {e}")


def save_last_user(username: str) -> None:
    st = load_state()
    st["last_user"] = username
    save_state(st)


def load_last_user() -> str:
    st = load_state()
    return (st.get("last_user") or "").strip()


# ============================
# UTILIDADES UI/THREAD
# ============================
def run_bg(master: tb.Window, fn, on_ok=None, on_err=None):
    """
    Ejecuta fn() en hilo para no congelar UI.
    on_ok(result) y on_err(exception) corren en el hilo principal.
    """

    def worker():
        try:
            res = fn()
            if on_ok:
                master.after(0, lambda: on_ok(res))
        except Exception as e:
            if on_err:
                master.after(0, lambda: on_err(e))
            else:
                master.after(0, lambda: messagebox.showerror("Error", str(e)))

    threading.Thread(target=worker, daemon=True).start()


def set_icon(window, logo_small=None):
    try:
        if logo_small is not None:
            window.iconphoto(False, logo_small)
        else:
            base_path = sys._MEIPASS if hasattr(sys, "_MEIPASS") else os.path.abspath(".")
            icon_path = os.path.join(base_path, "Vinder_logo.ico")
            window.iconbitmap(icon_path)
    except Exception as e:
        logger.info(f"No se pudo configurar el icono: {e}")


# ============================
# ACTUALIZACIONES (tufup)
# ============================
def check_for_updates():
    progress_window = tb.Toplevel()
    progress_window.title("Actualizando...")
    progress_window.geometry("330x110")
    progress_label = tb.Label(progress_window, text="Buscando/instalando actualizaciones...", font=("Helvetica", 10))
    progress_label.pack(pady=10)
    progress_bar = tb.Progressbar(progress_window, mode="indeterminate")
    progress_bar.pack(pady=10, padx=20, fill="x")
    progress_bar.start(10)

    def run_update():
        try:
            subprocess.run(
                ["tufup", "configure", "--repo-url", "https://github.com/Saidpc18/Flask_stripe_server/releases/latest"],
                check=True,
            )

            result = subprocess.run(["tufup", "check"], capture_output=True, text=True, check=True)

            if "New version available" in result.stdout:
                progress_bar.config(mode="determinate", maximum=100)
                process = subprocess.Popen(["tufup", "update"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                value = 40
                for _line in iter(process.stdout.readline, ""):
                    value = min(value + 5, 100)
                    progress_bar["value"] = value
                process.stdout.close()
                process.wait()

                progress_bar.stop()
                progress_window.destroy()
                messagebox.showinfo("Actualización", "Actualización instalada.\nReinicia la app para aplicar los cambios.")
            else:
                progress_bar.stop()
                progress_window.destroy()
                messagebox.showinfo("Actualización", "No hay actualizaciones disponibles.")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("Error", f"Error durante la actualización: {e}")

    threading.Thread(target=run_update, daemon=True).start()


# ============================
# CATÁLOGOS LOCALES
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
    "JM Semirremolque Tipo Jaula Ganadera": "B",
}

posicion_5 = {
    "5' X 10' A 14' Pies": "1",
    "5´ X 15´ A 20´Pies": "2",
    "6´ X 10´ A  14´ Pies": "3",
    "6´ X 15´ A  20´Pies": "4",
    "7´ X 10´ A  15´  Pies": "5",
    "7´ X 16´ A 21´ Pies": "6",
    "7´ X 22´ A 27´ Pies": "7",
    "8´ X 16´ A  21´ Pies": "8",
    "8´ X 22´ A  27´ Pies": "9",
    "8.5´ X 16´ A  21´ Pies": "A",
    "8.5´ X 22´ A 27´ Pies": "B",
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
    "3 Ejes, rin 24.5, 30 m3, 45.000, Suspensión de aire": "Z",
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
    "2101 A 2300": "A",
}

posicion_8 = {"Sin Frenos": "9", "Frenos de disco": "8", "Frenos Electricos": "7", "Frenos de Aire": "6"}
posicion_10 = {"2024": "R", "2025": "S", "2026": "T", "2027": "V", "2028": "W"}
posicion_11 = {"Ex Hacienda la Honda, Zacatecas, México": "A"}


# ============================
# APP GUI
# ============================
class VinderApp:
    def __init__(self, master: tb.Window):
        self.master = master
        self.master.title("Vinder")
        self.load_logo()
        set_icon(self.master, self.logo_photo_small)
        self.master.state("zoomed")

        # Estado
        self.usuario_actual = None
        self.result_label = None
        self.status_label = None

        # Frames (para evitar AttributeError)
        self.left_frame = None
        self.right_frame = None

        # Notificaciones (banner interno)
        self.toast_var = tb.StringVar(value="")
        self.toast_style = "secondary"

        # Licencia (badge + detalle)
        self.license_badge_var = tb.StringVar(value="LICENCIA: —")
        self.license_detail_var = tb.StringVar(value="")
        self.license_badge_label = None

        # Detalle de conversión (solo en ventana principal)
        self.conversion_frame = None
        self.conversion_text = None
        self.status_label = None  # (compatibilidad: por si existía el label viejo)

        # Catálogos
        self.var_wmi = tb.StringVar(value="3J9")
        self.var_c4 = tb.StringVar()
        self.var_c5 = tb.StringVar()
        self.var_c6 = tb.StringVar()
        self.var_c7 = tb.StringVar()
        self.var_c8 = tb.StringVar()
        self.var_c10 = tb.StringVar()
        self.var_c11 = tb.StringVar()

        # Transferencia (última orden)
        self.last_order_id = None

        self.main_frame = tb.Frame(self.master, padding=20)
        self.main_frame.pack(fill="both", expand=True)

        self.mostrar_ventana_inicio()

    # ----------------------------
    # LOGO
    # ----------------------------
    def load_logo(self):
        try:
            base_path = sys._MEIPASS if hasattr(sys, "_MEIPASS") else os.path.abspath(".")
            icon_path = os.path.join(base_path, "Vinder_logo.ico")
            original_logo = Image.open(icon_path)
            self.logo_small = original_logo.resize((32, 32), Image.Resampling.LANCZOS)
            self.logo_photo_small = ImageTk.PhotoImage(self.logo_small)
            self.logo_large = original_logo.resize((128, 128), Image.Resampling.LANCZOS)
            self.logo_photo_large = ImageTk.PhotoImage(self.logo_large)
        except Exception as e:
            logger.info(f"Error al cargar Vinder_logo.ico: {e}")
            self.logo_photo_small = None
            self.logo_photo_large = None

    # ----------------------------
    # NOTIFICATIONS
    # ----------------------------
    def show_toast(self, text: str, style: str = "secondary", ms: int = 4500):
        self.toast_var.set(text)
        self.toast_style = style
        if hasattr(self, "toast_label") and self.toast_label is not None:
            try:
                self.toast_label.configure(bootstyle=style)
            except Exception:
                pass

        def clear():
            self.toast_var.set("")

        if ms > 0:
            self.master.after(ms, clear)

    # ----------------------------
    # HELPERS API
    # ----------------------------
    def _require_user(self) -> bool:
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return False
        return True

    def _set_license_badge(self, active: bool, exp_text: str = ""):
        if active:
            self.license_badge_var.set("LICENCIA: ACTIVA")
            self.license_detail_var.set(f"Expira: {exp_text}" if exp_text else "")
            if self.license_badge_label:
                self.license_badge_label.configure(bootstyle="success")
        else:
            self.license_badge_var.set("LICENCIA: EXPIRADA")
            self.license_detail_var.set("")
            if self.license_badge_label:
                self.license_badge_label.configure(bootstyle="danger")

    def refresh_license_status(self):
        if not self._require_user():
            return

        def job():
            url1 = api_url("/license-status")
            resp1 = requests.get(url1, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp1.status_code == 200:
                return {"mode": "license-status", "data": safe_json(resp1)}

            if resp1.status_code == 404:
                url2 = api_url("/funcion-principal")
                resp2 = requests.get(url2, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
                d2 = safe_json(resp2)
                return {"mode": "funcion-principal", "status": resp2.status_code, "data": d2}

            d1 = safe_json(resp1)
            err = d1.get("error", f"HTTP {resp1.status_code}")
            raise RuntimeError(f"No se pudo consultar licencia: {err}")

        def ok(payload):
            mode = payload.get("mode")

            if mode == "license-status":
                data = payload.get("data", {})
                active = bool(data.get("active", False))
                exp = data.get("license_expiration_utc") or data.get("license_expiration_raw") or ""
                self._set_license_badge(active, exp_text=exp)
                return

            status = payload.get("status", 0)
            data = payload.get("data", {})
            active = bool(status == 200 and "message" in data)
            self._set_license_badge(active)

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Licencia", str(e)))

    def verificar_licencia(self) -> bool:
        if not self._require_user():
            return False
        try:
            url = api_url("/funcion-principal")
            resp = requests.get(url, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            data = safe_json(resp)

            if resp.status_code == 200 and "message" in data:
                return True

            msg = data.get("error", f"Suscripción requerida (HTTP {resp.status_code})")
            if messagebox.askyesno("Suscripción requerida", f"{msg}\n\n¿Quieres renovar ahora?"):
                self.ventana_renovar_licencia()
            return False

        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo verificar la licencia: {e}")
            return False

    # ----------------------------
    # PAGO TARJETA (STRIPE) - opcional
    # ----------------------------
    def iniciar_pago_stripe(self):
        if not self._require_user():
            return

        def job():
            server_url = api_url("/create-checkout-session")
            response = requests.post(server_url, json={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            data = safe_json(response)
            if response.status_code != 200:
                err = data.get("error", f"HTTP {response.status_code}")
                raise RuntimeError(err)
            url_pago = data.get("url", "")
            if not url_pago:
                raise RuntimeError("No se recibió URL de Stripe.")
            return url_pago

        def ok(url_pago: str):
            webbrowser.open(url_pago)
            self.show_toast("Stripe abierto en tu navegador.", style="success")
            self.refresh_license_status()

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Stripe", str(e)))

    # ----------------------------
    # VINs (Flask)
    # ----------------------------
    def guardar_vin_en_flask(self, vin_data: dict):
        if not self._require_user():
            return
        url = api_url("/guardar_vin")
        payload = {"user": self.usuario_actual, **vin_data}

        try:
            resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                self.show_toast("VIN guardado en PostgreSQL.", style="success")
            else:
                data = safe_json(resp)
                err = data.get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo guardar el VIN: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor: {e}")

    def ver_vins_en_flask(self):
        if not self._require_user():
            return []
        url = api_url("/ver_vins")
        try:
            resp = requests.get(url, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                data = safe_json(resp)
                return data.get("vins", [])
            data = safe_json(resp)
            err = data.get("error", f"HTTP {resp.status_code}")
            messagebox.showerror("Error", f"No se pudo obtener VINs: {err}")
            return []
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
            return []

    def obtener_secuencial_desde_servidor(self, year_code):
        if not self._require_user():
            return 0

        url = api_url("/obtener_secuencial")
        payload = {"user": self.usuario_actual, "year": year_code}

        try:
            resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                data = safe_json(resp)
                return data.get("secuencial", 0)
            data = safe_json(resp)
            err = data.get("error", f"HTTP {resp.status_code}")
            messagebox.showerror("Error", f"Error al obtener secuencial: {err}")
            return 0
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar a /obtener_secuencial: {e}")
            return 0

    def exportar_vins(self):
        if not self._require_user():
            return
        url = api_url("/export_vins")

        try:
            response = requests.get(url, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if response.status_code == 200:
                filename = filedialog.asksaveasfilename(
                    defaultextension=".xlsx",
                    filetypes=[("Excel files", "*.xlsx")],
                    title="Guardar lista de VINs",
                )
                if filename:
                    with open(filename, "wb") as f:
                        f.write(response.content)
                    self.show_toast("Archivo exportado correctamente.", style="success")
            else:
                data = safe_json(response)
                err = data.get("error", f"HTTP {response.status_code}")
                messagebox.showerror("Error", f"No se pudo exportar: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def eliminar_todos_vins(self):
        if not self._require_user():
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Eliminar TODOS los VINs?"):
            return

        try:
            url = api_url("/eliminar_todos_vins")
            resp = requests.post(url, json={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                self.show_toast("VINs eliminados y secuencial reiniciado.", style="warning")
            else:
                data = safe_json(resp)
                err = data.get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo eliminar: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    def eliminar_ultimo_vin(self):
        if not self._require_user():
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Eliminar el ÚLTIMO VIN?"):
            return

        try:
            url = api_url("/eliminar_ultimo_vins")
            resp = requests.post(url, json={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                self.show_toast("Último VIN eliminado.", style="warning")
            else:
                data = safe_json(resp)
                err = data.get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo eliminar: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    # ----------------------------
    # UI: ventanas
    # ----------------------------
    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

        # Limpieza de widgets sueltos (por si existía el label viejo de conversion)
        try:
            if getattr(self, "status_label", None) is not None:
                self.status_label.destroy()
        except Exception:
            pass
        self.status_label = None

        # Reset de referencias UI
        self.left_frame = None
        self.right_frame = None
        self.result_label = None
        self.conversion_frame = None
        self.conversion_text = None

    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Bienvenido a Vinder", font=("Helvetica", 22, "bold")).pack(pady=18)

        tb.Button(container, text="Crear Cuenta", bootstyle=PRIMARY, command=self.ventana_crear_cuenta).pack(
            pady=8, ipadx=16, ipady=4
        )
        tb.Button(container, text="Iniciar Sesión", bootstyle=INFO, command=self.ventana_iniciar_sesion).pack(
            pady=8, ipadx=16, ipady=4
        )

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Crear Cuenta", font=("Helvetica", 20, "bold")).pack(pady=10)

        def password_ok(p: str):
            if len(p) < 8:
                return False, "La contraseña debe tener al menos 8 caracteres."
            has_letter = any(c.isalpha() for c in p)
            has_digit = any(c.isdigit() for c in p)
            if not (has_letter and has_digit):
                return False, "La contraseña debe incluir al menos una letra y un número."
            return True, ""

        def set_pw_visibility():
            show = "" if show_pw_var.get() else "*"
            entry_reg_pass.configure(show=show)
            entry_reg_pass2.configure(show=show)

        tb.Label(container, text="Usuario:", font=("Helvetica", 14)).pack(pady=(10, 5))
        entry_reg_user = tb.Entry(container, font=("Helvetica", 14), width=28)
        entry_reg_user.pack()

        tb.Label(container, text="Contraseña:", font=("Helvetica", 14)).pack(pady=(12, 5))
        entry_reg_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=28)
        entry_reg_pass.pack()

        tb.Label(container, text="Confirmar contraseña:", font=("Helvetica", 14)).pack(pady=(12, 5))
        entry_reg_pass2 = tb.Entry(container, show="*", font=("Helvetica", 14), width=28)
        entry_reg_pass2.pack()

        show_pw_var = tb.BooleanVar(value=False)
        tb.Checkbutton(
            container,
            text="Mostrar contraseñas",
            variable=show_pw_var,
            command=set_pw_visibility,
            bootstyle="secondary",
        ).pack(pady=(8, 0))

        btn_registrar = tb.Button(container, text="Registrar", bootstyle=SUCCESS)
        btn_registrar.pack(pady=14, ipadx=12, ipady=4)

        def do_register():
            username = entry_reg_user.get().strip()
            password = entry_reg_pass.get().strip()
            password2 = entry_reg_pass2.get().strip()

            if not username or not password or not password2:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            if password != password2:
                messagebox.showerror("Error", "Las contraseñas no coinciden.")
                return

            ok, msg = password_ok(password)
            if not ok:
                messagebox.showerror("Error", msg)
                return

            btn_registrar.configure(state="disabled", text="Registrando…")
            register_url = api_url("/register")

            def job():
                r = requests.post(
                    register_url,
                    json={"username": username, "password": password},
                    timeout=HTTP_TIMEOUT
                )
                return r.status_code, safe_json(r)

            def on_ok(result):
                btn_registrar.configure(state="normal", text="Registrar")
                status, data = result
                if status == 201:
                    self.show_toast("Cuenta creada. Inicia sesión.", style="success")
                    save_last_user(username)
                    self.mostrar_ventana_inicio()
                else:
                    err = data.get("error", f"HTTP {status}")
                    messagebox.showerror("Error", f"Registro fallido: {err}")

            def on_err(e):
                btn_registrar.configure(state="normal", text="Registrar")
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

            run_bg(self.master, job, on_ok=on_ok, on_err=on_err)

        btn_registrar.configure(command=do_register)

        tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio).pack(
            pady=5, ipadx=12, ipady=3
        )

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Iniciar Sesión", font=("Helvetica", 20, "bold")).pack(pady=10)

        tb.Label(container, text="Usuario:", font=("Helvetica", 14)).pack(pady=(10, 5))
        entry_user = tb.Entry(container, font=("Helvetica", 14), width=28)
        entry_user.pack()

        last = load_last_user()
        if last:
            entry_user.insert(0, last)

        tb.Label(container, text="Contraseña:", font=("Helvetica", 14)).pack(pady=(12, 5))
        entry_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=28)
        entry_pass.pack()

        show_pw = tb.BooleanVar(value=False)

        def toggle_pw():
            entry_pass.configure(show="" if show_pw.get() else "*")

        tb.Checkbutton(container, text="Mostrar contraseña", variable=show_pw, command=toggle_pw, bootstyle="secondary").pack(pady=(6, 0))

        btn_login = tb.Button(container, text="Iniciar Sesión", bootstyle=PRIMARY)
        btn_login.pack(pady=14, ipadx=14, ipady=4)

        def do_login():
            user = entry_user.get().strip()
            pw = entry_pass.get().strip()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            btn_login.configure(state="disabled", text="Entrando…")
            login_url = api_url("/login")

            def job():
                response = requests.post(login_url, json={"username": user, "password": pw}, timeout=HTTP_TIMEOUT)
                return response.status_code, safe_json(response), user

            def on_ok(result):
                status, data, user_ = result
                btn_login.configure(state="normal", text="Iniciar Sesión")

                if status == 200:
                    self.usuario_actual = user_
                    save_last_user(user_)
                    self.show_toast(f"Bienvenido, {user_}", style="success")
                    self.ventana_principal()
                    self.refresh_license_status()
                else:
                    err = data.get("error", f"HTTP {status}")
                    messagebox.showerror("Error", f"Login fallido: {err}")

            def on_err(e):
                btn_login.configure(state="normal", text="Iniciar Sesión")
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

            run_bg(self.master, job, on_ok=on_ok, on_err=on_err)

        btn_login.configure(command=do_login)

        tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio).pack(
            pady=5, ipadx=12, ipady=3
        )

    def ventana_principal(self):
        self.limpiar_main_frame()

        # TOP BAR
        top = tb.Frame(self.main_frame, padding=10)
        top.pack(fill="x")

        if self.logo_photo_small is not None:
            tb.Label(top, image=self.logo_photo_small).pack(side="left", padx=(0, 8))

        tb.Label(top, text="Vinder", font=("Helvetica", 18, "bold")).pack(side="left")
        tb.Label(top, text=f" | Usuario: {self.usuario_actual}", font=("Helvetica", 11)).pack(side="left", padx=8)

        self.license_badge_label = tb.Label(
            top,
            textvariable=self.license_badge_var,
            bootstyle="secondary",
            font=("Helvetica", 10, "bold"),
            padding=(10, 4),
        )
        self.license_badge_label.pack(side="left", padx=10)
        tb.Label(top, textvariable=self.license_detail_var, font=("Helvetica", 10)).pack(side="left")

        tb.Button(top, text="Refrescar licencia", bootstyle=SECONDARY, command=self.refresh_license_status).pack(side="right")

        # NOTIFICATION BANNER
        self.toast_label = tb.Label(self.main_frame, textvariable=self.toast_var, bootstyle="secondary", anchor="center")
        self.toast_label.pack(fill="x", pady=(6, 10))

        # BODY (3 columnas: izquierda / centro / acciones)
        body = tb.Frame(self.main_frame, padding=10)
        body.pack(fill="both", expand=True)

        body.columnconfigure(0, weight=3, uniform="cols")
        body.columnconfigure(1, weight=3, uniform="cols")
        body.columnconfigure(2, weight=2, uniform="cols")
        body.rowconfigure(0, weight=1)

        left = tb.Labelframe(body, text="Generar VIN", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        center = tb.Labelframe(body, text="Detalle de conversión (pos.9)", padding=16)
        center.grid(row=0, column=1, sticky="nsew", padx=(0, 10))

        right = tb.Labelframe(body, text="Acciones", padding=16)
        right.grid(row=0, column=2, sticky="nsew")

        self.left_frame = left
        self.right_frame = right
        self.conversion_frame = center

        # --- Columna izquierda ---
        tb.Label(left, text="Código WMI:", font=("Helvetica", 12)).pack(anchor="w")
        tb.Entry(left, textvariable=self.var_wmi, font=("Helvetica", 12), width=12).pack(anchor="w", pady=(0, 10))

        self.crear_optionmenus(left)

        tb.Separator(left).pack(fill="x", pady=12)

        self.result_label = tb.Label(left, text="VIN/NIV: —", font=("Helvetica", 16, "bold"))
        self.result_label.pack(anchor="w", pady=(8, 4))

        # --- Columna central (detalle) ---
        tb.Label(
            center,
            text="Aquí verás el detalle del cálculo del dígito verificador (pos.9) cuando generes un VIN.",
            font=("Helvetica", 10),
            wraplength=500,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        self.conversion_text = ScrolledText(center, wrap="word", font=("Helvetica", 10), height=22)
        self.conversion_text.pack(fill="both", expand=True)
        self.conversion_text.insert("end", "Genera un VIN para ver el detalle aquí.")
        self.conversion_text.configure(state="disabled")

        # --- Acciones ---
        tb.Button(
            right,
            text="Generar VIN",
            bootstyle=PRIMARY,
            command=self.generar_vin
        ).pack(fill="x", pady=(0, 10), ipady=10)

        tb.Button(right, text="Renovar Licencia", bootstyle=SUCCESS, command=self.ventana_renovar_licencia).pack(fill="x", pady=6, ipady=4)
        tb.Button(right, text="Ver VINs Generados", bootstyle=INFO, command=self.ventana_lista_vins).pack(fill="x", pady=6, ipady=4)
        tb.Button(right, text="Exportar VINs a Excel", bootstyle=INFO, command=self.exportar_vins).pack(fill="x", pady=6, ipady=4)
        tb.Button(right, text="Eliminar TODOS los VINs", bootstyle=WARNING, command=self.eliminar_todos_vins).pack(fill="x", pady=6, ipady=4)
        tb.Button(right, text="Eliminar ÚLTIMO VIN", bootstyle=WARNING, command=self.eliminar_ultimo_vin).pack(fill="x", pady=6, ipady=4)

        tb.Separator(right).pack(fill="x", pady=10)

        tb.Button(right, text="Buscar actualizaciones", bootstyle=SECONDARY, command=check_for_updates).pack(fill="x", pady=6, ipady=4)
        tb.Button(right, text="Cerrar Sesión", bootstyle=DANGER, command=self.cerrar_sesion).pack(fill="x", pady=6, ipady=4)

    def ventana_renovar_licencia(self):
        if not self._require_user():
            return

        win = tb.Toplevel(self.master)
        win.title("Renovar Licencia")
        set_icon(win, self.logo_photo_small)
        win.geometry("820x520")

        stripe_frame = tb.Labelframe(win, text="Tarjeta (Stripe)", padding=12)
        stripe_frame.pack(fill="x", padx=12, pady=10)
        tb.Label(stripe_frame, text="Si Stripe está habilitado en el servidor, se abrirá el checkout en tu navegador.").pack(anchor="w")
        tb.Button(stripe_frame, text="Pagar con tarjeta", bootstyle=SUCCESS, command=self.iniciar_pago_stripe).pack(anchor="w", pady=6)

    def crear_optionmenus(self, parent):
        def valor_inicial(dic):
            return list(dic.keys())[0] if dic else ""

        if not self.var_c4.get():
            self.var_c4.set(valor_inicial(posicion_4))
        if not self.var_c5.get():
            self.var_c5.set(valor_inicial(posicion_5))
        if not self.var_c6.get():
            self.var_c6.set(valor_inicial(posicion_6))
        if not self.var_c7.get():
            self.var_c7.set(valor_inicial(posicion_7))
        if not self.var_c8.get():
            self.var_c8.set(valor_inicial(posicion_8))
        if not self.var_c10.get():
            self.var_c10.set(valor_inicial(posicion_10))
        if not self.var_c11.get():
            self.var_c11.set(valor_inicial(posicion_11))

        tb.Label(parent, text="Pos.4 (Modelo):", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c4, self.var_c4.get(), *posicion_4.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.5:", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c5, self.var_c5.get(), *posicion_5.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.6:", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c6, self.var_c6.get(), *posicion_6.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.7:", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c7, self.var_c7.get(), *posicion_7.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.8:", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c8, self.var_c8.get(), *posicion_8.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.10 (Año):", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c10, self.var_c10.get(), *posicion_10.keys()).pack(anchor="w", pady=(0, 8))

        tb.Label(parent, text="Pos.11 (Planta):", font=("Helvetica", 12)).pack(anchor="w")
        tb.OptionMenu(parent, self.var_c11, self.var_c11.get(), *posicion_11.keys()).pack(anchor="w", pady=(0, 8))

    def generar_vin(self):
        if not self.verificar_licencia():
            return

        wmi = self.var_wmi.get().strip().upper()
        c4 = posicion_4.get(self.var_c4.get(), "")
        c5 = posicion_5.get(self.var_c5.get(), "")
        c6 = posicion_6.get(self.var_c6.get(), "")
        c7 = posicion_7.get(self.var_c7.get(), "")
        c8 = posicion_8.get(self.var_c8.get(), "")
        c10 = posicion_10.get(self.var_c10.get(), "")
        c11 = posicion_11.get(self.var_c11.get(), "")

        if not (wmi and c4 and c5 and c6 and c7 and c8 and c10 and c11):
            messagebox.showerror("Error", "Faltan datos en uno de los catálogos.")
            return

        sec = self.obtener_secuencial_desde_servidor(c10)
        if sec == 0:
            return

        sec_str = str(sec).zfill(3)
        fixed_12_14 = "098"

        valores_sin_pos9 = f"{wmi}{c4}{c5}{c6}{c7}{c8}{c10}{c11}{fixed_12_14}{sec_str}"
        pos9 = self.calcular_posicion_9(valores_sin_pos9)
        vin_completo = f"{wmi}{c4}{c5}{c6}{c7}{c8}{pos9}{c10}{c11}{fixed_12_14}{sec_str}"

        vin_data = {
            "wmi": wmi,
            "c4": c4,
            "c5": c5,
            "c6": c6,
            "c7": c7,
            "c8": c8,
            "c10": c10,
            "c11": c11,
            "pos9": pos9,
            "fixed_12_14": fixed_12_14,
            "secuencial": sec_str,
            "vin_completo": vin_completo,
        }
        self.guardar_vin_en_flask(vin_data)

        if self.result_label:
            self.result_label.config(text=f"VIN/NIV: {vin_completo}", font=("Helvetica", 18, "bold"))

    def calcular_posicion_9(self, valores: str) -> str:
        sustituciones = {
            "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
            "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2,
            "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
        }
        for i in range(10):
            sustituciones[str(i)] = i

        weights = [8, 7, 6, 5, 4, 3, 2, 10, 9, 8, 7, 6, 5, 4, 3, 2]

        suma = 0
        mapping = []
        for i, char in enumerate(valores[:16]):
            valor_num = sustituciones.get(char, 0)
            peso = weights[i]
            valor_ponderado = valor_num * peso
            mapping.append(f"'{char}'→{valor_num} * {peso} = {valor_ponderado}")
            suma += valor_ponderado

        resultado_modulo = suma % 11
        digito_verificador = "X" if resultado_modulo == 10 else str(resultado_modulo)

        mitad = len(mapping) // 2
        conversion_details = (
            "Detalle de la conversión:\n"
            + "    ".join(mapping[:mitad]) + "\n"
            + "    ".join(mapping[mitad:]) + "\n"
            + f"Suma total ponderada: {suma}\n"
            + f"Módulo 11: {resultado_modulo}\n"
            + f"Dígito verificador: {digito_verificador}"
        )

        # Mostrar detalle SOLO en la columna central de la ventana principal
        if self.conversion_text:
            self.conversion_text.configure(state="normal")
            self.conversion_text.delete("1.0", "end")
            self.conversion_text.insert("end", conversion_details)
            self.conversion_text.configure(state="disabled")
            self.conversion_text.yview_moveto(0)

        return digito_verificador

    def ventana_lista_vins(self):
        if not self.verificar_licencia():
            return

        vins = self.ver_vins_en_flask()
        vins_window = tb.Toplevel(self.master)
        vins_window.title("VINs Generados")
        set_icon(vins_window, self.logo_photo_small)
        vins_window.geometry("650x450")

        st = ScrolledText(vins_window, wrap="none", font=("Helvetica", 12, "bold"), height=20)
        st.pack(fill="both", expand=True)

        texto_vins = ""
        for vin in vins:
            vin_completo = vin.get("vin_completo", "VIN no disponible")
            fecha_crea = vin.get("created_at", "")
            texto_vins += f"VIN Completo: {vin_completo}\nCreado: {fecha_crea}\n" + ("-" * 40 + "\n")

        st.insert("end", texto_vins)
        st.configure(state="disabled")

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.last_order_id = None
        self.license_badge_var.set("LICENCIA: —")
        self.license_detail_var.set("")
        self.show_toast("")
        self.mostrar_ventana_inicio()


# ============================
# MAIN
# ============================
if __name__ == "__main__":
    app_tk = tb.Window(themename="sandstone")
    app_tk.title("Vinder")
    set_icon(app_tk)
    VinderApp(app_tk)
    app_tk.mainloop()
