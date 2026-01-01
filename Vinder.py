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
# PERSISTENCIA LOCAL (último order_id por usuario)
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

        # Estado licencia (UI)
        self.license_status_var = tb.StringVar(value="Estado de licencia: (sin verificar)")

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
    # HELPERS API
    # ----------------------------
    def _require_user(self) -> bool:
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return False
        return True

    def refresh_license_status(self):
        """
        Intenta /license-status (si existe). Si no existe (404), hace fallback a /funcion-principal.
        """
        if not self._require_user():
            return

        def job():
            # 1) try /license-status
            url1 = api_url("/license-status")
            resp1 = requests.get(url1, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp1.status_code == 200:
                return {"mode": "license-status", "data": safe_json(resp1)}

            # si no existe, fallback
            if resp1.status_code == 404:
                url2 = api_url("/funcion-principal")
                resp2 = requests.get(url2, params={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
                d2 = safe_json(resp2)
                return {"mode": "funcion-principal", "status": resp2.status_code, "data": d2}

            # otros errores
            d1 = safe_json(resp1)
            err = d1.get("error", f"HTTP {resp1.status_code}")
            raise RuntimeError(f"No se pudo consultar licencia: {err}")

        def ok(payload):
            mode = payload.get("mode")
            if mode == "license-status":
                data = payload.get("data", {})
                active = data.get("active", False)
                exp = data.get("license_expiration_utc") or data.get("license_expiration_raw")
                if active:
                    self.license_status_var.set(f"Estado de licencia: ACTIVA (expira: {exp})")
                else:
                    self.license_status_var.set("Estado de licencia: EXPIRADA / INACTIVA")
                return

            # fallback /funcion-principal
            status = payload.get("status", 0)
            data = payload.get("data", {})
            if status == 200 and "message" in data:
                self.license_status_var.set("Estado de licencia: ACTIVA")
            else:
                self.license_status_var.set("Estado de licencia: EXPIRADA / INACTIVA")

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
            messagebox.showinfo("Pago Iniciado", "Se abrió Stripe en tu navegador.")
            self.refresh_license_status()

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Stripe", str(e)))

    # ----------------------------
    # TRANSFERENCIA SPEI
    # ----------------------------
    def _load_last_order_id(self):
        if not self.usuario_actual:
            return None
        st = load_state()
        return st.get("transfer_orders", {}).get(self.usuario_actual)

    def _save_last_order_id(self, order_id: str):
        if not self.usuario_actual:
            return
        st = load_state()
        st.setdefault("transfer_orders", {})
        st["transfer_orders"][self.usuario_actual] = order_id
        save_state(st)

    def _apply_transfer_ui(self, ui, data: dict):
        ui["status_var"].set(data.get("status", ""))
        ui["amount_var"].set(str(data.get("amount_mxn", "")))
        ui["ref_var"].set(data.get("reference", ""))
        ui["clabe_var"].set(data.get("clabe", ""))
        ui["bank_var"].set(data.get("bank_name", ""))
        ui["benef_var"].set(data.get("beneficiary_name", ""))
        ui["expires_var"].set(data.get("expires_at", ""))

        instructions = data.get("instructions", [])
        ui["instructions_box"].configure(state="normal")
        ui["instructions_box"].delete("1.0", "end")
        ui["instructions_box"].insert("end", "\n".join(instructions))
        ui["instructions_box"].configure(state="disabled")

    def stop_transfer_polling(self, ui):
        after_id = ui.get("_poll_after_id")
        if after_id:
            try:
                self.master.after_cancel(after_id)
            except Exception:
                pass
        ui["_poll_after_id"] = None

    def start_transfer_polling(self, ui, interval_ms=10000, max_minutes=30, notify_popup=True):
        """
        Polling a /transfer-instructions hasta:
          - status == confirmed (refresca licencia + popup opcional)
          - status in (expired, rejected)
          - deadline
        """
        if not self._require_user():
            return

        self.stop_transfer_polling(ui)
        ui["_poll_deadline"] = time.monotonic() + max_minutes * 60

        # si notify_popup=False, evitamos popup aunque llegue confirmed
        if not notify_popup:
            ui["_confirmed_notified"] = True
        else:
            ui.setdefault("_confirmed_notified", False)

        def tick():
            win = ui.get("_window")
            if win is None or not win.winfo_exists():
                self.stop_transfer_polling(ui)
                return

            order_id = ui["order_id_var"].get().strip()
            if not order_id:
                self.stop_transfer_polling(ui)
                return

            def job():
                resp = requests.get(
                    api_url("/transfer-instructions"),
                    params={"order_id": order_id, "user": self.usuario_actual},
                    timeout=HTTP_TIMEOUT,
                )
                data = safe_json(resp)
                if resp.status_code != 200:
                    err = data.get("error", f"HTTP {resp.status_code}")
                    raise RuntimeError(err)
                return data

            def ok(data):
                self._apply_transfer_ui(ui, data)
                st = (data.get("status") or "").lower()

                if st == "confirmed":
                    self.refresh_license_status()
                    if not ui.get("_confirmed_notified", False):
                        ui["_confirmed_notified"] = True
                        messagebox.showinfo("Transferencia confirmada", "Pago confirmado. Tu licencia ya está activa.")
                    self.stop_transfer_polling(ui)
                    return

                if st in ("expired", "rejected"):
                    self.stop_transfer_polling(ui)
                    return

                if time.monotonic() < ui.get("_poll_deadline", 0):
                    ui["_poll_after_id"] = self.master.after(interval_ms, tick)
                else:
                    self.stop_transfer_polling(ui)

            def err(_e: Exception):
                # errores transitorios: seguimos hasta deadline
                if time.monotonic() < ui.get("_poll_deadline", 0):
                    ui["_poll_after_id"] = self.master.after(interval_ms, tick)
                else:
                    self.stop_transfer_polling(ui)

            run_bg(self.master, job, on_ok=ok, on_err=err)

        ui["_poll_after_id"] = self.master.after(1000, tick)

    def crear_orden_transferencia(self, ui):
        if not self._require_user():
            return

        def job():
            resp = requests.post(
                api_url("/create-transfer-order"),
                json={"user": self.usuario_actual},
                timeout=HTTP_TIMEOUT,
            )
            data = safe_json(resp)
            if resp.status_code not in (200, 201):
                err = data.get("error", f"HTTP {resp.status_code}")
                raise RuntimeError(err)
            return data

        def ok(data):
            # reinicia polling (por si venía de otra orden)
            self.stop_transfer_polling(ui)
            ui["_confirmed_notified"] = False

            self.last_order_id = data.get("order_id")
            if self.last_order_id:
                self._save_last_order_id(self.last_order_id)

            ui["order_id_var"].set(data.get("order_id", ""))
            ui["amount_var"].set(str(data.get("amount_mxn", "")))
            ui["ref_var"].set(data.get("reference", ""))
            ui["clabe_var"].set(data.get("clabe", ""))
            ui["bank_var"].set(data.get("bank_name", ""))
            ui["benef_var"].set(data.get("beneficiary_name", ""))
            ui["expires_var"].set(data.get("expires_at", ""))
            ui["status_var"].set(data.get("status", "pending"))

            instructions = data.get("instructions", [])
            ui["instructions_box"].configure(state="normal")
            ui["instructions_box"].delete("1.0", "end")
            ui["instructions_box"].insert("end", "\n".join(instructions))
            ui["instructions_box"].configure(state="disabled")

            messagebox.showinfo("Transferencia", "Orden SPEI creada. Copia monto + referencia y realiza tu SPEI.")

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Transferencia", str(e)))

    def actualizar_instrucciones_transferencia(self, ui):
        if not self._require_user():
            return

        order_id = ui["order_id_var"].get().strip()
        if not order_id:
            messagebox.showerror("Transferencia", "Primero crea una orden (order_id vacío).")
            return

        def job():
            resp = requests.get(
                api_url("/transfer-instructions"),
                params={"order_id": order_id, "user": self.usuario_actual},
                timeout=HTTP_TIMEOUT,
            )
            data = safe_json(resp)
            if resp.status_code != 200:
                err = data.get("error", f"HTTP {resp.status_code}")
                raise RuntimeError(err)
            return data

        def ok(data):
            self._apply_transfer_ui(ui, data)

            st = (data.get("status") or "").lower()
            if st == "confirmed":
                self.refresh_license_status()

            # si ya está submitted y no hay polling activo, arráncalo
            if st == "submitted" and not ui.get("_poll_after_id"):
                self.start_transfer_polling(ui, interval_ms=10000, max_minutes=30, notify_popup=True)

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Transferencia", str(e)))

    def enviar_tracking_key(self, ui):
        if not self._require_user():
            return

        order_id = ui["order_id_var"].get().strip()
        tracking_key = ui["tracking_var"].get().strip()
        if not order_id or not tracking_key:
            messagebox.showerror("Transferencia", "Falta order_id o tracking_key.")
            return

        def job():
            resp = requests.post(
                api_url("/transfer-submit"),
                json={"order_id": order_id, "tracking_key": tracking_key},
                timeout=HTTP_TIMEOUT,
            )
            data = safe_json(resp)
            if resp.status_code != 200:
                err = data.get("error", f"HTTP {resp.status_code}")
                raise RuntimeError(err)
            return data

        def ok(data):
            ui["status_var"].set(data.get("status", "submitted"))
            messagebox.showinfo("Transferencia", "Tracking recibido. Se validará manualmente en CEP.")
            self.actualizar_instrucciones_transferencia(ui)
            # ✅ POLLING AUTOMÁTICO para detectar confirmación
            self.start_transfer_polling(ui, interval_ms=10000, max_minutes=30, notify_popup=True)

        run_bg(self.master, job, on_ok=ok, on_err=lambda e: messagebox.showerror("Transferencia", str(e)))

    # ----------------------------
    # VINs
    # ----------------------------
    def guardar_vin_en_flask(self, vin_data: dict):
        if not self._require_user():
            return
        url = api_url("/guardar_vin")
        payload = {"user": self.usuario_actual, **vin_data}

        try:
            resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "VIN guardado en PostgreSQL.")
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
                    messagebox.showinfo("Éxito", f"Archivo exportado: {filename}")
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
                messagebox.showinfo("Éxito", "VINs eliminados y secuencial reiniciado.")
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
            url = api_url("/eliminar_ultimo_vin")
            resp = requests.post(url, json={"user": self.usuario_actual}, timeout=HTTP_TIMEOUT)
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "Último VIN eliminado.")
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

    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Bienvenido a Vinder", font=("Helvetica", 22, "bold")).pack(pady=20)

        tb.Button(container, text="Crear Cuenta", bootstyle=PRIMARY, command=self.ventana_crear_cuenta).pack(
            pady=10, ipadx=10
        )
        tb.Button(container, text="Iniciar Sesión", bootstyle=INFO, command=self.ventana_iniciar_sesion).pack(
            pady=10, ipadx=10
        )

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Crear Cuenta", font=("Helvetica", 20, "bold")).pack(pady=10)

        tb.Label(container, text="Usuario:", font=("Helvetica", 14)).pack(pady=5)
        entry_reg_user = tb.Entry(container, font=("Helvetica", 14), width=25)
        entry_reg_user.pack()

        tb.Label(container, text="Contraseña:", font=("Helvetica", 14)).pack(pady=5)
        entry_reg_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=25)
        entry_reg_pass.pack()

        def do_register():
            username = entry_reg_user.get().strip()
            password = entry_reg_pass.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            register_url = api_url("/register")
            try:
                response = requests.post(register_url, json={"username": username, "password": password}, timeout=HTTP_TIMEOUT)
                if response.status_code == 201:
                    messagebox.showinfo("Éxito", "Cuenta creada. Ahora inicia sesión.")
                    self.mostrar_ventana_inicio()
                else:
                    data = safe_json(response)
                    err = data.get("error", f"HTTP {response.status_code}")
                    messagebox.showerror("Error", f"Registro fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

        tb.Button(container, text="Registrar", bootstyle=SUCCESS, command=do_register).pack(pady=10, ipadx=10)
        tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio).pack(
            pady=5, ipadx=10
        )

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=10)

        tb.Label(container, text="Iniciar Sesión", font=("Helvetica", 20, "bold")).pack(pady=10)

        tb.Label(container, text="Usuario:", font=("Helvetica", 14)).pack(pady=5)
        entry_user = tb.Entry(container, font=("Helvetica", 14), width=25)
        entry_user.pack()

        tb.Label(container, text="Contraseña:", font=("Helvetica", 14)).pack(pady=5)
        entry_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=25)
        entry_pass.pack()

        def do_login():
            user = entry_user.get().strip()
            pw = entry_pass.get().strip()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            login_url = api_url("/login")
            try:
                response = requests.post(login_url, json={"username": user, "password": pw}, timeout=HTTP_TIMEOUT)
                if response.status_code == 200:
                    self.usuario_actual = user
                    messagebox.showinfo("Éxito", f"Bienvenido, {user}")
                    self.ventana_principal()
                    self.refresh_license_status()
                else:
                    data = safe_json(response)
                    err = data.get("error", f"HTTP {response.status_code}")
                    messagebox.showerror("Error", f"Login fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

        tb.Button(container, text="Iniciar Sesión", bootstyle=PRIMARY, command=do_login).pack(pady=10, ipadx=10)
        tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio).pack(
            pady=5, ipadx=10
        )

    def ventana_principal(self):
        self.limpiar_main_frame()

        top = tb.Frame(self.main_frame, padding=10)
        top.pack(fill="x")

        tb.Label(top, text=f"Hola, {self.usuario_actual}", font=("Helvetica", 16, "bold")).pack(side="left")
        tb.Label(top, textvariable=self.license_status_var, font=("Helvetica", 11)).pack(side="left", padx=20)
        tb.Button(top, text="Refrescar licencia", bootstyle=SECONDARY, command=self.refresh_license_status).pack(side="left")

        body = tb.Frame(self.main_frame, padding=10)
        body.pack(fill="both", expand=True)

        self.left_frame = tb.Frame(body, padding=20)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = tb.Frame(body, padding=20)
        self.right_frame.pack(side="right", fill="both", expand=True)

        tb.Label(self.left_frame, text="Generar VIN", font=("Helvetica", 14, "underline")).pack(pady=5)
        tb.Label(self.left_frame, text="Código WMI:", font=("Helvetica", 12)).pack()
        tb.Entry(self.left_frame, textvariable=self.var_wmi, font=("Helvetica", 12), width=10).pack()
        self.crear_optionmenus(self.left_frame)

        tb.Button(self.right_frame, text="Generar VIN", bootstyle=PRIMARY, command=self.generar_vin).pack(pady=10, ipadx=5)

        self.result_label = tb.Label(self.right_frame, text="VIN/NIV: ", font=("Helvetica", 12))
        self.result_label.pack(pady=5)

        tb.Button(self.right_frame, text="Renovar Licencia", bootstyle=SUCCESS, command=self.ventana_renovar_licencia).pack(
            pady=10, ipadx=5
        )
        tb.Button(self.right_frame, text="Ver VINs Generados", bootstyle=INFO, command=self.ventana_lista_vins).pack(
            pady=5, ipadx=5
        )
        tb.Button(self.right_frame, text="Exportar VINs a Excel", bootstyle=INFO, command=self.exportar_vins).pack(
            pady=5, ipadx=5
        )
        tb.Button(self.right_frame, text="Eliminar TODOS los VINs", bootstyle=WARNING, command=self.eliminar_todos_vins).pack(
            pady=5, ipadx=5
        )
        tb.Button(self.right_frame, text="Eliminar ÚLTIMO VIN", bootstyle=WARNING, command=self.eliminar_ultimo_vin).pack(
            pady=5, ipadx=5
        )
        tb.Button(self.right_frame, text="Buscar actualizaciones", bootstyle=SECONDARY, command=check_for_updates).pack(
            pady=10, ipadx=5
        )
        tb.Button(self.right_frame, text="Cerrar Sesión", bootstyle=DANGER, command=self.cerrar_sesion).pack(pady=10, ipadx=5)

    def ventana_renovar_licencia(self):
        if not self._require_user():
            return

        win = tb.Toplevel(self.master)
        win.title("Renovar Licencia")
        set_icon(win, self.logo_photo_small)
        win.geometry("820x520")

        ui = {
            "order_id_var": tb.StringVar(value=""),
            "amount_var": tb.StringVar(value=""),
            "ref_var": tb.StringVar(value=""),
            "clabe_var": tb.StringVar(value=""),
            "bank_var": tb.StringVar(value=""),
            "benef_var": tb.StringVar(value=""),
            "expires_var": tb.StringVar(value=""),
            "status_var": tb.StringVar(value=""),
            "tracking_var": tb.StringVar(value=""),
            "instructions_box": None,
        }

        ui["_window"] = win

        def on_close():
            self.stop_transfer_polling(ui)
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

        stripe_frame = tb.Labelframe(win, text="Tarjeta (Stripe)", padding=12)
        stripe_frame.pack(fill="x", padx=12, pady=10)
        tb.Label(stripe_frame, text="Si Stripe está habilitado en el servidor, se abrirá el checkout en tu navegador.").pack(anchor="w")
        tb.Button(stripe_frame, text="Pagar con tarjeta", bootstyle=SUCCESS, command=self.iniciar_pago_stripe).pack(anchor="w", pady=6)

        transfer_frame = tb.Labelframe(win, text="Transferencia SPEI (validación manual CEP)", padding=12)
        transfer_frame.pack(fill="both", expand=True, padx=12, pady=10)

        row1 = tb.Frame(transfer_frame)
        row1.pack(fill="x", pady=4)

        tb.Button(row1, text="Crear orden SPEI", bootstyle=PRIMARY, command=lambda: self.crear_orden_transferencia(ui)).pack(side="left")
        tb.Button(row1, text="Actualizar estado/instrucciones", bootstyle=INFO, command=lambda: self.actualizar_instrucciones_transferencia(ui)).pack(side="left", padx=6)

        last = self._load_last_order_id()
        if last:
            ui["order_id_var"].set(last)
            self.last_order_id = last

            def boot():
                self.actualizar_instrucciones_transferencia(ui)
                # polling “silencioso” al abrir (sin popup)
                self.start_transfer_polling(ui, interval_ms=10000, max_minutes=30, notify_popup=False)

            self.master.after(200, boot)

        def copy_to_clip(text_: str):
            if not text_:
                return
            self.master.clipboard_clear()
            self.master.clipboard_append(text_)
            messagebox.showinfo("Copiado", "Copiado al portapapeles.")

        grid = tb.Frame(transfer_frame)
        grid.pack(fill="x", pady=8)

        def add_row(r, label, var, copy_btn=False):
            tb.Label(grid, text=label, width=18).grid(row=r, column=0, sticky="w", pady=2)
            e = tb.Entry(grid, textvariable=var, width=55)
            e.grid(row=r, column=1, sticky="w", pady=2)
            e.configure(state="readonly")
            if copy_btn:
                tb.Button(grid, text="Copiar", bootstyle=SECONDARY, command=lambda: copy_to_clip(var.get())).grid(row=r, column=2, padx=6)

        add_row(0, "Status:", ui["status_var"])
        add_row(1, "Order ID:", ui["order_id_var"], copy_btn=True)
        add_row(2, "Monto MXN:", ui["amount_var"])
        add_row(3, "Referencia:", ui["ref_var"], copy_btn=True)
        add_row(4, "CLABE:", ui["clabe_var"], copy_btn=True)
        add_row(5, "Banco:", ui["bank_var"])
        add_row(6, "Beneficiario:", ui["benef_var"])
        add_row(7, "Expira:", ui["expires_var"])

        tb.Label(transfer_frame, text="Tracking key (clave de rastreo):").pack(anchor="w", pady=(10, 2))
        track_row = tb.Frame(transfer_frame)
        track_row.pack(fill="x")

        tb.Entry(track_row, textvariable=ui["tracking_var"], width=50).pack(side="left")
        tb.Button(track_row, text="Enviar tracking", bootstyle=SUCCESS, command=lambda: self.enviar_tracking_key(ui)).pack(side="left", padx=8)

        tb.Label(transfer_frame, text="Instrucciones / Estado:").pack(anchor="w", pady=(10, 2))
        box = ScrolledText(transfer_frame, wrap="word", height=8, font=("Helvetica", 10))
        box.pack(fill="both", expand=True)
        box.insert("end", "Crea una orden para ver instrucciones aquí.")
        box.configure(state="disabled")
        ui["instructions_box"] = box

    def crear_optionmenus(self, parent):
        def valor_inicial(dic):
            return list(dic.keys())[0] if dic else ""

        tb.Label(parent, text="Pos.4 (Modelo):", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c4, valor_inicial(posicion_4), *posicion_4.keys()).pack()

        tb.Label(parent, text="Pos.5:", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c5, valor_inicial(posicion_5), *posicion_5.keys()).pack()

        tb.Label(parent, text="Pos.6:", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c6, valor_inicial(posicion_6), *posicion_6.keys()).pack()

        tb.Label(parent, text="Pos.7:", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c7, valor_inicial(posicion_7), *posicion_7.keys()).pack()

        tb.Label(parent, text="Pos.8:", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c8, valor_inicial(posicion_8), *posicion_8.keys()).pack()

        tb.Label(parent, text="Pos.10 (Año):", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c10, valor_inicial(posicion_10), *posicion_10.keys()).pack()

        tb.Label(parent, text="Pos.11 (Planta):", font=("Helvetica", 12)).pack()
        tb.OptionMenu(parent, self.var_c11, valor_inicial(posicion_11), *posicion_11.keys()).pack()

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
        self.result_label.config(text=f"VIN/NIV: {vin_completo}", font=("Helvetica", 24, "bold"))

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

        if self.status_label:
            self.status_label.config(text=conversion_details)
        else:
            self.status_label = tb.Label(
                self.master,
                text=conversion_details,
                font=("Helvetica", 10),
                bootstyle="secondary",
                anchor="center",
                justify="center",
                wraplength=900,
            )
            self.status_label.pack(side="bottom", fill="x", pady=5)

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

        btn_frame = tb.Frame(vins_window)
        btn_frame.pack(fill="x", pady=5)

        tb.Button(btn_frame, text="Eliminar TODOS los VINs", bootstyle=DANGER, command=self.eliminar_todos_vins).pack(side="left", padx=5)
        tb.Button(btn_frame, text="Eliminar ÚLTIMO VIN", bootstyle=DANGER, command=self.eliminar_ultimo_vin).pack(side="left", padx=5)

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.last_order_id = None
        self.license_status_var.set("Estado de licencia: (sin verificar)")
        self.mostrar_ventana_inicio()


# ============================
# MAIN
# ============================
if __name__ == "__main__":
    app_tk = tb.Window(themename="sandstone")
    app_tk.title("Vinder - ttkbootstrap Edition")
    set_icon(app_tk)
    VinderApp(app_tk)
    app_tk.mainloop()
