import os
import sys
import io
import logging
from datetime import datetime, timedelta
import subprocess
import threading
import bcrypt
import pandas as pd
import stripe
import requests
import webbrowser
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import xlsxwriter
from PIL import Image, ImageTk  # Importar Pillow

# ============================
# CONFIGURACIÓN DE LOGGING
# ============================
logging.basicConfig(
    level=logging.INFO,  # Cambia a INFO o WARNING en producción
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================
# FUNCIONES PARA ICONO Y ACTUALIZACIONES
# ============================
def set_icon(window, logo_small=None):
    try:
        if logo_small is not None:
            window.iconphoto(False, logo_small)
        else:
            # Si no se pasó imagen, intenta cargar el icono desde el directorio actual o desde _MEIPASS (PyInstaller)
            base_path = sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.abspath(".")
            icon_path = os.path.join(base_path, "Vinder_logo.ico")
            window.iconbitmap(icon_path)
    except Exception as e:
        print("No se pudo configurar el icono:", e)


def check_for_updates():
    """
    Verifica si hay una versión más reciente disponible usando 'tufup'.
    Si se detecta una nueva versión, muestra una ventana con una barra de progreso mientras se ejecuta la actualización.
    La URL del repositorio se configura en: https://github.com/Saidpc18/Flask_stripe_server/releases/latest
    """
    # Crear una ventana de progreso
    progress_window = tb.Toplevel()
    progress_window.title("Actualizando...")
    progress_window.geometry("300x100")
    progress_label = tb.Label(progress_window, text="Instalando actualizaciones, por favor espere...", font=("Helvetica", 10))
    progress_label.pack(pady=10)
    progress_bar = tb.Progressbar(progress_window, mode="indeterminate")
    progress_bar.pack(pady=10, padx=20, fill="x")
    progress_bar.start(10)

    def run_update():
        try:
            # Configurar el repositorio de actualizaciones con la URL de GitHub Releases
            subprocess.run(["tufup", "configure", "--repo-url", "https://github.com/Saidpc18/Flask_stripe_server/releases/latest"], check=True)
            progress_bar.step(20)
            # Verificar actualizaciones
            result = subprocess.run(["tufup", "check"], capture_output=True, text=True, check=True)
            progress_bar.step(20)
            if "New version available" in result.stdout:
                progress_bar.config(mode="determinate", maximum=100)
                # Iniciar actualización y leer la salida para mostrar el progreso
                process = subprocess.Popen(["tufup", "update"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                progress_value = 40
                for line in iter(process.stdout.readline, ""):
                    progress_value = min(progress_value + 5, 100)
                    progress_bar['value'] = progress_value
                process.stdout.close()
                process.wait()
                progress_bar.stop()
                progress_window.destroy()
                messagebox.showinfo("Actualización", "La aplicación se ha actualizado correctamente.\nReinicia la aplicación para aplicar los cambios.")
            else:
                progress_bar.stop()
                progress_window.destroy()
                messagebox.showinfo("Actualización", "No hay actualizaciones disponibles.")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("Error", f"Error durante la actualización: {e}")

    threading.Thread(target=run_update).start()


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
    "JM Semirremolque Tipo Jaula Ganadera": "B"
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
# CLASE DE LA APLICACIÓN GUI
# ============================
class VinderApp:
    def __init__(self, master: tb.Window):
        self.master = master
        self.master.title("Vinder")
        self.load_logo()
        set_icon(self.master, self.logo_photo_small)
        self.master.state("zoomed")
        # Variables de estado
        self.var_wmi = tb.StringVar(value="3J9")
        self.var_c4 = tb.StringVar()
        self.var_c5 = tb.StringVar()
        self.var_c6 = tb.StringVar()
        self.var_c7 = tb.StringVar()
        self.var_c8 = tb.StringVar()
        self.var_c10 = tb.StringVar()
        self.var_c11 = tb.StringVar()
        self.usuario_actual = None
        self.result_label = None
        self.status_label = None
        self.main_frame = tb.Frame(self.master, padding=20)
        self.main_frame.pack(fill="both", expand=True)
        self.mostrar_ventana_inicio()

    def load_logo(self):
        try:
            original_logo = Image.open("Vinder_logo.ico")
            self.logo_small = original_logo.resize((32, 32), Image.Resampling.LANCZOS)
            self.logo_photo_small = ImageTk.PhotoImage(self.logo_small)
            self.logo_large = original_logo.resize((128, 128), Image.Resampling.LANCZOS)
            self.logo_photo_large = ImageTk.PhotoImage(self.logo_large)
        except Exception as e:
            print("Error al cargar el logo Vinder_logo.ico:", e)
            self.logo_photo_small = None
            self.logo_photo_large = None

    # ----------------------------
    # MÉTODOS PARA LLAMADAS AL SERVIDOR
    # ----------------------------
    def iniciar_pago(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "Inicia sesión para realizar el pago.")
            return
        try:
            server_url = "https://flask-stripe-server.onrender.com/create-checkout-session"
            response = requests.post(server_url, json={"user": self.usuario_actual})
            if response.status_code == 200:
                data = response.json()
                url_pago = data.get("url", "")
                if url_pago:
                    webbrowser.open(url_pago)
                    messagebox.showinfo("Pago Iniciado", "Se abrió la página de pago en tu navegador.")
                else:
                    messagebox.showerror("Error", "No se recibió una URL válida del servidor.")
            else:
                err = response.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo iniciar el proceso de pago: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def verificar_licencia(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return False
        try:
            url = "https://flask-stripe-server.onrender.com/funcion-principal"
            resp = requests.get(url, params={"user": self.usuario_actual})
            data = resp.json()
            if resp.status_code == 403 or "error" in data:
                msg = data.get("error", "Licencia inválida.")
                messagebox.showerror("Suscripción requerida", msg)
                return False
            return True
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo verificar la licencia: {e}")
            return False

    def guardar_vin_en_flask(self, vin_data: dict):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return
        url = "https://flask-stripe-server.onrender.com/guardar_vin"
        payload = {"user": self.usuario_actual, **vin_data}
        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "VIN guardado en PostgreSQL.")
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo guardar el VIN: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor Flask: {e}")

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
                messagebox.showerror("Error", f"No se pudo obtener VINs: {err}")
                return []
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
            return []

    def obtener_secuencial_desde_servidor(self, year_code):
        url = "https://flask-stripe-server.onrender.com/obtener_secuencial"
        payload = {"user": self.usuario_actual, "year": year_code}
        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                sec = data.get("secuencial", 0)
                # Utiliza el secuencial tal como lo devuelve el servidor
                return sec
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"Error al obtener secuencial: {err}")
                return 0
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar a /obtener_secuencial: {e}")
            return 0

    def exportar_vins(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return
        url = f"https://flask-stripe-server.onrender.com/export_vins?user={self.usuario_actual}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                filename = filedialog.asksaveasfilename(
                    defaultextension=".xlsx",
                    filetypes=[("Excel files", "*.xlsx")],
                    title="Guardar lista de VINs"
                )
                if filename:
                    with open(filename, "wb") as f:
                        f.write(response.content)
                    messagebox.showinfo("Éxito", f"Archivo exportado exitosamente: {filename}")
                else:
                    messagebox.showinfo("Exportar VINs", "Exportación cancelada.")
            else:
                err = response.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo exportar los VINs: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def eliminar_todos_vins(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Estás seguro que deseas eliminar TODOS los VINs?"):
            return
        try:
            url = "https://flask-stripe-server.onrender.com/eliminar_todos_vins"
            resp = requests.post(url, json={"user": self.usuario_actual})
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "Todos los VINs han sido eliminados y el secuencial se ha reiniciado.")
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo eliminar todos los VINs: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    def eliminar_ultimo_vin(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Estás seguro que deseas eliminar el ÚLTIMO VIN?"):
            return
        try:
            url = "https://flask-stripe-server.onrender.com/eliminar_ultimo_vin"
            resp = requests.post(url, json={"user": self.usuario_actual})
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "El último VIN ha sido eliminado y el secuencial se ha actualizado.")
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo eliminar el último VIN: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    # ----------------------------
    # MÉTODOS DE GESTIÓN DE VENTANAS
    # ----------------------------
    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            logo_label = tb.Label(container, image=self.logo_photo_large)
            logo_label.pack(pady=10)

        lbl = tb.Label(container, text="Bienvenido a Vinder", font=("Helvetica", 22, "bold"))
        lbl.pack(pady=20)

        btn_crear = tb.Button(container, text="Crear Cuenta", bootstyle=PRIMARY, command=self.ventana_crear_cuenta)
        btn_crear.pack(pady=10, ipadx=10)

        btn_login = tb.Button(container, text="Iniciar Sesión", bootstyle=INFO, command=self.ventana_iniciar_sesion)
        btn_login.pack(pady=10, ipadx=10)

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            logo_label = tb.Label(container, image=self.logo_photo_large)
            logo_label.pack(pady=10)

        lbl_title = tb.Label(container, text="Crear Cuenta", font=("Helvetica", 20, "bold"))
        lbl_title.pack(pady=10)

        lbl_user = tb.Label(container, text="Usuario:", font=("Helvetica", 14))
        lbl_user.pack(pady=5)
        entry_reg_user = tb.Entry(container, font=("Helvetica", 14), width=25)
        entry_reg_user.pack()

        lbl_pass = tb.Label(container, text="Contraseña:", font=("Helvetica", 14))
        lbl_pass.pack(pady=5)
        entry_reg_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=25)
        entry_reg_pass.pack()

        def do_register():
            username = entry_reg_user.get().strip()
            password = entry_reg_pass.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Completa todos los campos.")
                return
            register_url = "https://flask-stripe-server.onrender.com/register"
            try:
                response = requests.post(register_url, json={"username": username, "password": password})
                if response.status_code == 201:
                    messagebox.showinfo("Éxito", "Cuenta creada exitosamente. Ahora puedes iniciar sesión.")
                    self.mostrar_ventana_inicio()
                else:
                    data = response.json()
                    err = data.get("error", "Error desconocido")
                    messagebox.showerror("Error", f"Registro fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectarse con el servidor: {e}")

        btn_reg = tb.Button(container, text="Registrar", bootstyle=SUCCESS, command=do_register)
        btn_reg.pack(pady=10, ipadx=10)

        btn_volver = tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio)
        btn_volver.pack(pady=5, ipadx=10)

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        if self.logo_photo_large is not None:
            logo_label = tb.Label(container, image=self.logo_photo_large)
            logo_label.pack(pady=10)

        lbl_title = tb.Label(container, text="Iniciar Sesión", font=("Helvetica", 20, "bold"))
        lbl_title.pack(pady=10)

        lbl_user = tb.Label(container, text="Usuario:", font=("Helvetica", 14))
        lbl_user.pack(pady=5)
        entry_user = tb.Entry(container, font=("Helvetica", 14), width=25)
        entry_user.pack()

        lbl_pass = tb.Label(container, text="Contraseña:", font=("Helvetica", 14))
        lbl_pass.pack(pady=5)
        entry_pass = tb.Entry(container, show="*", font=("Helvetica", 14), width=25)
        entry_pass.pack()

        def do_login():
            user = entry_user.get().strip()
            pw = entry_pass.get().strip()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return
            login_url = "https://flask-stripe-server.onrender.com/login"
            try:
                response = requests.post(login_url, json={"username": user, "password": pw})
                if response.status_code == 200:
                    messagebox.showinfo("Éxito", f"Bienvenido, {user}")
                    self.usuario_actual = user
                    self.ventana_principal()
                else:
                    data = response.json()
                    err = data.get("error", "Error desconocido")
                    messagebox.showerror("Error", f"Login fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

        btn_login = tb.Button(container, text="Iniciar Sesión", bootstyle=PRIMARY, command=do_login)
        btn_login.pack(pady=10, ipadx=10)

        btn_volver = tb.Button(container, text="Volver", bootstyle=SECONDARY, command=self.mostrar_ventana_inicio)
        btn_volver.pack(pady=5, ipadx=10)

    def ventana_principal(self):
        self.limpiar_main_frame()
        self.left_frame = tb.Frame(self.main_frame, padding=20)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = tb.Frame(self.main_frame, padding=20)
        self.right_frame.pack(side="right", fill="both", expand=True)

        lbl_title = tb.Label(self.main_frame, text=f"Hola, {self.usuario_actual}", font=("Helvetica", 16, "bold"))
        lbl_title.pack(pady=10)

        tb.Label(self.left_frame, text="Generar VIN", font=("Helvetica", 14, "underline")).pack(pady=5)
        tb.Label(self.left_frame, text="Código WMI:", font=("Helvetica", 12)).pack()
        tb.Entry(self.left_frame, textvariable=self.var_wmi, font=("Helvetica", 12), width=10).pack()

        self.crear_optionmenus(self.left_frame)

        tb.Button(self.right_frame, text="Generar VIN", bootstyle=PRIMARY, command=self.generar_vin).pack(pady=10, ipadx=5)

        self.result_label = tb.Label(self.right_frame, text="VIN/NIV: ", font=("Helvetica", 12))
        self.result_label.pack(pady=5)

        tb.Button(self.right_frame, text="Renovar Licencia", bootstyle=SUCCESS, command=self.iniciar_pago).pack(pady=10, ipadx=5)
        tb.Button(self.right_frame, text="Ver VINs Generados", bootstyle=INFO, command=self.ventana_lista_vins).pack(pady=5, ipadx=5)
        tb.Button(self.right_frame, text="Exportar VINs a Excel", bootstyle=INFO, command=self.exportar_vins).pack(pady=5, ipadx=5)
        tb.Button(self.right_frame, text="Eliminar TODOS los VINs", bootstyle=WARNING, command=self.eliminar_todos_vins).pack(pady=5, ipadx=5)
        tb.Button(self.right_frame, text="Eliminar ÚLTIMO VIN", bootstyle=WARNING, command=self.eliminar_ultimo_vin).pack(pady=5, ipadx=5)
        tb.Button(self.right_frame, text="Buscar actualizaciones", bootstyle=SECONDARY, command=check_for_updates).pack(pady=10, ipadx=5)
        tb.Button(self.right_frame, text="Cerrar Sesión", bootstyle=DANGER, command=self.cerrar_sesion).pack(pady=10, ipadx=5)

    def crear_optionmenus(self, parent):
        def valor_inicial(dic):
            return list(dic.keys())[0] if dic else ""

        tb.Label(parent, text="Pos.4 (Modelo):", font=("Helvetica", 12)).pack()
        self.menu_c4 = tb.OptionMenu(parent, self.var_c4, valor_inicial(posicion_4), *posicion_4.keys())
        self.menu_c4.pack()

        tb.Label(parent, text="Pos.5:", font=("Helvetica", 12)).pack()
        self.menu_c5 = tb.OptionMenu(parent, self.var_c5, valor_inicial(posicion_5), *posicion_5.keys())
        self.menu_c5.pack()

        tb.Label(parent, text="Pos.6:", font=("Helvetica", 12)).pack()
        self.menu_c6 = tb.OptionMenu(parent, self.var_c6, valor_inicial(posicion_6), *posicion_6.keys())
        self.menu_c6.pack()

        tb.Label(parent, text="Pos.7:", font=("Helvetica", 12)).pack()
        self.menu_c7 = tb.OptionMenu(parent, self.var_c7, valor_inicial(posicion_7), *posicion_7.keys())
        self.menu_c7.pack()

        tb.Label(parent, text="Pos.8:", font=("Helvetica", 12)).pack()
        self.menu_c8 = tb.OptionMenu(parent, self.var_c8, valor_inicial(posicion_8), *posicion_8.keys())
        self.menu_c8.pack()

        tb.Label(parent, text="Pos.10 (Año):", font=("Helvetica", 12)).pack()
        self.menu_c10 = tb.OptionMenu(parent, self.var_c10, valor_inicial(posicion_10), *posicion_10.keys())
        self.menu_c10.pack()

        tb.Label(parent, text="Pos.11 (Planta):", font=("Helvetica", 12)).pack()
        self.menu_c11 = tb.OptionMenu(parent, self.var_c11, valor_inicial(posicion_11), *posicion_11.keys())
        self.menu_c11.pack()

    def generar_vin(self):
        # Verificamos suscripción/licencia
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        # Obtenemos los valores elegidos
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

        # Obtenemos un secuencial desde el servidor
        sec = self.obtener_secuencial_desde_servidor(c10)
        if sec == 0:
            return

        sec_str = str(sec).zfill(3)
        fixed_12_14 = "098"

        # Se arma el VIN sin la posición 9 para poder calcular el dígito verificador
        valores_sin_pos9 = f"{wmi}{c4}{c5}{c6}{c7}{c8}{c10}{c11}{fixed_12_14}{sec_str}"

        # Calculamos la posición 9 con la función que multiplica por pesos
        pos9 = self.calcular_posicion_9(valores_sin_pos9)

        # Formamos el VIN final
        vin_completo = f"{wmi}{c4}{c5}{c6}{c7}{c8}{pos9}{c10}{c11}{fixed_12_14}{sec_str}"

        # Guardamos en el servidor
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

        # Mostramos en la interfaz
        if self.result_label:
            self.result_label.config(text=f"VIN/NIV: {vin_completo}", font=("Helvetica", 24, "bold"))
        else:
            self.result_label = tb.Label(self.right_frame, text=f"VIN/NIV: {vin_completo}", font=("Helvetica", 24, "bold"))
            self.result_label.pack(pady=5)

    def calcular_posicion_9(self, valores):
        """
        Calcula el dígito verificador (posición 9) del VIN,
        aplicando los pesos (8,7,6,5,4,3,2,10,9,8,7,6,5,4,3,2) a cada carácter convertido.
        Además, muestra en una barra de estado el detalle de la conversión.
        """

        # Diccionario de sustituciones de caracteres a valores numéricos
        sustituciones = {
            "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
            "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2,
            "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9
        }
        # Agregamos también las sustituciones para dígitos
        for i in range(10):
            sustituciones[str(i)] = i

        # Pesos para cada posición del VIN (excepto que la 9na se revisa como check digit)
        weights = [8, 7, 6, 5, 4, 3, 2, 10, 9, 8, 7, 6, 5, 4, 3, 2]

        mapping = []
        suma = 0

        # Convertimos cada carácter y lo multiplicamos por su peso
        for i, char in enumerate(valores):
            valor_num = sustituciones.get(char, 0)
            peso = weights[i]  # tomamos el peso según la posición
            valor_ponderado = valor_num * peso
            mapping.append(f"'{char}'→{valor_num} * {peso} = {valor_ponderado}")
            suma += valor_ponderado

        # Mostramos el detalle de la conversión en dos líneas para mayor legibilidad
        mitad = len(mapping) // 2
        linea1 = "    ".join(mapping[:mitad])
        linea2 = "    ".join(mapping[mitad:])

        conversion_details = (
            "Detalle de la conversión:\n"
            + linea1 + "\n"
            + linea2 + "\n"
            + f"Suma total ponderada: {suma}\n"
        )

        # Cálculo de dígito verificador (módulo 11)
        resultado_modulo = suma % 11
        conversion_details += f"Módulo 11: {resultado_modulo}\n"

        # Asignación del dígito verificador (10 se representa como 'X')
        digito_verificador = "X" if resultado_modulo == 10 else str(resultado_modulo)
        conversion_details += f"Dígito verificador: {digito_verificador}"

        # Mostrar el resultado en la barra de estado o crearlo si no existe
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
                wraplength=600
            )
            self.status_label.pack(side="bottom", fill="x", pady=5)

        return digito_verificador

    def ventana_lista_vins(self):
        """Muestra la lista de VINs generados en una ventana secundaria (Toplevel)."""
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        vins = self.ver_vins_en_flask()
        vins_window = tb.Toplevel(self.master)
        vins_window.title("VINs Generados")
        set_icon(vins_window, self.logo_photo_small)
        vins_window.geometry("500x400")

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

        btn_eliminar_todos = tb.Button(btn_frame, text="Eliminar TODOS los VINs", bootstyle=DANGER,
                                       command=self.eliminar_todos_vins)
        btn_eliminar_todos.pack(side="left", padx=5)

        btn_eliminar_ultimo = tb.Button(btn_frame, text="Eliminar ÚLTIMO VIN", bootstyle=DANGER,
                                        command=self.eliminar_ultimo_vin)
        btn_eliminar_ultimo.pack(side="left", padx=5)

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.mostrar_ventana_inicio()


# ----------------------------
# EJECUCIÓN DEL PROGRAMA
# ----------------------------
if __name__ == "__main__":
    app_tk = tb.Window(themename="sandstone")
    app_tk.title("Vinder - ttkbootstrap Edition")
    set_icon(app_tk)  # Se establece el icono; si se empaqueta, se utilizará sys._MEIPASS
    VinderApp(app_tk)
    app_tk.mainloop()
