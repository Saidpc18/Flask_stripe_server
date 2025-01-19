
import tkinter as tk
import requests  # Para enviar solicitudes HTTP al servidor Flask
import webbrowser  # Para abrir la URL de Stripe en el navegador
from tkinter import ttk, messagebox

# ============================
#   CATÁLOGOS (LOCALES)
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

catalogos = {
    "posicion_4": posicion_4,
    "posicion_5": posicion_5,
    "posicion_6": posicion_6,
    "posicion_7": posicion_7,
    "posicion_8": posicion_8,
    "posicion_10": posicion_10,
    "posicion_11": posicion_11,
}

# ============================
#  CLASE PRINCIPAL
# ============================
class VINBuilderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("VIN Builder - con PostgreSQL")

        # Pantalla completa o maximizada
        self.master.state("zoomed")  # O self.master.attributes("-fullscreen", True)

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

    # -----------------------------------------------------
    #  FUNCIONES QUE SE COMUNICAN CON EL SERVIDOR FLASK
    # -----------------------------------------------------
    def iniciar_pago(self):
        """Conecta con Flask (/create-checkout-session) para renovar licencia."""
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
                    messagebox.showerror("Error",
                                         "No se recibió una URL válida del servidor.")
            else:
                error_msg = response.json().get("error", "Error desconocido")
                messagebox.showerror("Error",
                                     f"No se pudo iniciar el proceso de pago: {error_msg}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error inesperado: {e}")

    def verificar_licencia(self):
        """
        Llama al endpoint /funcion-principal en el servidor Flask
        para verificar si la licencia está activa.
        """
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

    def guardar_vin_en_flask(self, vin_data):
        """Llama al endpoint /guardar_vin para guardar VIN en la base de datos."""
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
                # VIN guardado con éxito
                messagebox.showinfo("Éxito", "VIN guardado correctamente (en PostgreSQL).")
            else:
                data = resp.json()
                err = data.get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo guardar el VIN: {err}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor Flask: {e}")

    def ver_vins_en_flask(self):
        """Llama al endpoint /ver_vins para obtener VINs del usuario."""
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        url = "https://flask-stripe-server.onrender.com/ver_vins"
        try:
            resp = requests.get(url, params={"user": self.usuario_actual})
            if resp.status_code == 200:
                data = resp.json()
                vins = data.get("vins", [])
                return vins
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"No se pudo obtener la lista de VINs: {err}")
                return []
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Error al conectarse al servidor Flask: {e}")
            return []

    # -----------------------------------------------------
    #  VENTANAS DE INICIO / LOGIN
    # -----------------------------------------------------
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

        ttk.Label(self.main_frame, text="Crear Cuenta", font=("Arial", 14, "bold")).pack(pady=10)

        ttk.Label(self.main_frame, text="Usuario:").pack()
        entry_reg_user = ttk.Entry(self.main_frame)
        entry_reg_user.pack()

        ttk.Label(self.main_frame, text="Contraseña:").pack()
        entry_reg_pass = ttk.Entry(self.main_frame, show="*")
        entry_reg_pass.pack()

        def do_register():
            username = entry_reg_user.get().strip()
            password = entry_reg_pass.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            # Utiliza la URL de tu servidor en producción (o de prueba)
            register_url = "https://flask-stripe-server.onrender.com/register"
            try:
                response = requests.post(register_url, json={"username": username, "password": password})
                if response.status_code == 201:
                    messagebox.showinfo("Éxito", "Cuenta creada exitosamente. Ahora puedes iniciar sesión.")
                    self.mostrar_ventana_inicio()  # Regresa a la pantalla principal de inicio de sesión
                else:
                    data = response.json()
                    err = data.get("error", "Error desconocido")
                    messagebox.showerror("Error", f"Registro fallido: {err}")
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Error al conectarse con el servidor: {e}")

        ttk.Button(self.main_frame, text="Registrar", command=do_register).pack(pady=10)
        ttk.Button(self.main_frame, text="Volver", command=self.mostrar_ventana_inicio).pack(pady=5)

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
            pw = entry_pass.get().strip()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            login_url = "https://flask-stripe-server.onrender.com/login"  # O la URL de producción
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
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

        ttk.Button(self.main_frame, text="Iniciar Sesión",
                   command=do_login).pack(pady=10)

        ttk.Button(self.main_frame, text="Volver",
                   command=self.mostrar_ventana_inicio).pack()

    # -----------------------------------------------------
    #  VENTANA PRINCIPAL (POST-LOGIN)
    # -----------------------------------------------------
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
        """Genera VIN localmente y luego lo guarda en Flask (PostgreSQL)."""
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
        sec = datetime.now().strftime("%H%M%S")  # secuencial

        # Construye el VIN completo (ejemplo de concatenación; ajústalo a tu lógica)
        vin_completo = f"{wmi}{c4}{c5}{c6}{c7}{c8}{c10}{c11}{sec}"

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

        # Envía a Flask
        self.guardar_vin_en_flask(vin_data)

        # Actualiza la etiqueta de resultado con el VIN completo en letra grande
        if self.result_label:
            self.result_label.config(text=f"VIN/NIV: {vin_completo}", font=("Arial", 24, "bold"))
        else:
            self.result_label = ttk.Label(self.right_frame, text=f"VIN/NIV: {vin_completo}", font=("Arial", 24, "bold"))
            self.result_label.pack(pady=5)

    def ventana_lista_vins(self):
        """Obtiene VINs desde Flask (PostgreSQL) y los muestra."""
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

        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        texto_vins = ""
        for vin in vins:
            # Suponiendo que se debe usar un WMI predefinido (o podrías guardarlo en la entrada) y que el VIN se
            # construye concatenando las partes de la misma forma que en 'generar_vin'
            # Por ejemplo, se asume que el VIN completo es: WMI + c4 + c5 + c6 + c7 + c8 + c10 + c11 + secuencial
            # Ajusta la concatenación según tu lógica.
            vin_completo = f"3J9{vin['c4']}{vin['c5']}{vin['c6']}{vin['c7']}{vin['c8']}{vin['c10']}{vin['c11']}{vin['secuencial']}"
            texto_vins += f"VIN Completo: {vin_completo}\n"
            fecha_crea = vin.get("created_at", "")
            texto_vins += f"Creado: {fecha_crea}\n"
            texto_vins += "-" * 40 + "\n"

        # Usa una fuente mayor para mostrar el VIN
        ttk.Label(scroll_frame, text=texto_vins, justify=tk.LEFT, font=("Arial", 14, "bold")).pack(pady=10)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.mostrar_ventana_inicio()

    def ventana_editar_tablas(self):
        # Método existente para editar catálogos (local)
        pass


# ============================
#  PUNTO DE ENTRADA
# ============================
if __name__ == "__main__":
    root = tk.Tk()
    app = VINBuilderApp(root)
    root.mainloop()
