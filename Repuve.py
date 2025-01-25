import requests
import webbrowser
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox

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
    "5´ X 15´ A 20´Pies": "2",
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

class VINBuilderApp:
    def __init__(self, master: tb.Window):
        self.master = master
        self.master.title("VIN Builder - con PostgreSQL (ttkbootstrap)")

        # Ocupa casi toda la pantalla
        self.master.state("zoomed")

        # Variables
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

        # Frame principal
        self.main_frame = tb.Frame(self.master, padding=20)
        self.main_frame.pack(fill="both", expand=True)

        self.mostrar_ventana_inicio()

    # ============================
    #   LLAMADAS AL SERVIDOR
    # ============================
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
                                        "Se abrió la página de pago en tu navegador.")
                else:
                    messagebox.showerror("Error", "No se recibió una URL válida del servidor.")
            else:
                err = response.json().get("error", "Error desconocido")
                messagebox.showerror("Error",
                                     f"No se pudo iniciar el proceso de pago: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def verificar_licencia(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return False
        try:
            url = "https://flask-stripe-server.onrender.com/funcion-principal"
            response = requests.get(url, params={"user": self.usuario_actual})
            data = response.json()
            if response.status_code == 403 or "error" in data:
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
        """
        Llama a /obtener_secuencial en Flask y retorna el secuencial (int).
        """
        url = "https://flask-stripe-server.onrender.com/obtener_secuencial"
        payload = {"user": self.usuario_actual, "year": year_code}
        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("secuencial", 0)
            else:
                err = resp.json().get("error", "Error desconocido")
                messagebox.showerror("Error", f"Error al obtener secuencial: {err}")
                return 0
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar a /obtener_secuencial: {e}")
            return 0

    # ============================
    #       VENTANAS
    # ============================
    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()

        # Centramos los widgets en un Frame interno
        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        lbl = tb.Label(container, text="Bienvenido a VIN Builder",
                       font=("Helvetica", 22, "bold"))
        lbl.pack(pady=20)

        btn_crear = tb.Button(container, text="Crear Cuenta", bootstyle=PRIMARY,
                              command=self.ventana_crear_cuenta)
        btn_crear.pack(pady=10, ipadx=10)

        btn_login = tb.Button(container, text="Iniciar Sesión", bootstyle=INFO,
                              command=self.ventana_iniciar_sesion)
        btn_login.pack(pady=10, ipadx=10)

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()

        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        lbl_title = tb.Label(container, text="Crear Cuenta",
                             font=("Helvetica", 20, "bold"))
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
                response = requests.post(register_url,
                                         json={"username": username, "password": password})
                if response.status_code == 201:
                    messagebox.showinfo("Éxito",
                                        "Cuenta creada exitosamente. Ahora puedes iniciar sesión.")
                    self.mostrar_ventana_inicio()
                else:
                    data = response.json()
                    err = data.get("error", "Error desconocido")
                    messagebox.showerror("Error", f"Registro fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectarse con el servidor: {e}")

        btn_reg = tb.Button(container, text="Registrar", bootstyle=SUCCESS,
                            command=do_register)
        btn_reg.pack(pady=10, ipadx=10)

        btn_volver = tb.Button(container, text="Volver", bootstyle=SECONDARY,
                               command=self.mostrar_ventana_inicio)
        btn_volver.pack(pady=5, ipadx=10)

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()

        container = tb.Frame(self.main_frame, padding=40)
        container.pack(expand=True)

        lbl_title = tb.Label(container, text="Iniciar Sesión",
                             font=("Helvetica", 20, "bold"))
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
                response = requests.post(login_url,
                                         json={"username": user, "password": pw})
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

        btn_login = tb.Button(container, text="Iniciar Sesión", bootstyle=PRIMARY,
                              command=do_login)
        btn_login.pack(pady=10, ipadx=10)

        btn_volver = tb.Button(container, text="Volver", bootstyle=SECONDARY,
                               command=self.mostrar_ventana_inicio)
        btn_volver.pack(pady=5, ipadx=10)

    def ventana_principal(self):
        self.limpiar_main_frame()

        # Frames
        self.left_frame = tb.Frame(self.main_frame, padding=20)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = tb.Frame(self.main_frame, padding=20)
        self.right_frame.pack(side="right", fill="both", expand=True)

        lbl_title = tb.Label(self.main_frame,
                             text=f"Hola, {self.usuario_actual}",
                             font=("Helvetica", 16, "bold"))
        lbl_title.pack(pady=10)

        tb.Label(self.left_frame, text="Generar VIN",
                 font=("Helvetica", 14, "underline")).pack(pady=5)

        tb.Label(self.left_frame, text="Código WMI:", font=("Helvetica", 12)).pack()
        tb.Entry(self.left_frame, textvariable=self.var_wmi, font=("Helvetica", 12), width=10).pack()

        self.crear_optionmenus(self.left_frame)

        tb.Button(self.right_frame, text="Generar VIN", bootstyle=PRIMARY,
                  command=self.generar_vin).pack(pady=10, ipadx=5)

        self.result_label = tb.Label(self.right_frame, text="VIN/NIV: ", font=("Helvetica", 12))
        self.result_label.pack(pady=5)

        tb.Button(self.right_frame, text="Renovar Licencia", bootstyle=SUCCESS,
                  command=self.iniciar_pago).pack(pady=10, ipadx=5)

        tb.Button(self.right_frame, text="Ver VINs Generados", bootstyle=INFO,
                  command=self.ventana_lista_vins).pack(pady=5, ipadx=5)

        tb.Button(self.right_frame, text="Cerrar Sesión", bootstyle=DANGER,
                  command=self.cerrar_sesion).pack(pady=10, ipadx=5)

    def crear_optionmenus(self, parent):
        # Helper para OptionMenus
        def valor_inicial(dic):
            return list(dic.keys())[0] if dic else ""

        # Pos.4
        tb.Label(parent, text="Pos.4 (Modelo):", font=("Helvetica", 12)).pack()
        self.menu_c4 = tb.OptionMenu(parent, self.var_c4, valor_inicial(posicion_4), *posicion_4.keys())
        self.menu_c4.pack()

        # Pos.5
        tb.Label(parent, text="Pos.5:", font=("Helvetica", 12)).pack()
        self.menu_c5 = tb.OptionMenu(parent, self.var_c5, valor_inicial(posicion_5), *posicion_5.keys())
        self.menu_c5.pack()

        # Pos.6
        tb.Label(parent, text="Pos.6:", font=("Helvetica", 12)).pack()
        self.menu_c6 = tb.OptionMenu(parent, self.var_c6, valor_inicial(posicion_6), *posicion_6.keys())
        self.menu_c6.pack()

        # Pos.7
        tb.Label(parent, text="Pos.7:", font=("Helvetica", 12)).pack()
        self.menu_c7 = tb.OptionMenu(parent, self.var_c7, valor_inicial(posicion_7), *posicion_7.keys())
        self.menu_c7.pack()

        # Pos.8
        tb.Label(parent, text="Pos.8:", font=("Helvetica", 12)).pack()
        self.menu_c8 = tb.OptionMenu(parent, self.var_c8, valor_inicial(posicion_8), *posicion_8.keys())
        self.menu_c8.pack()

        # Pos.10
        tb.Label(parent, text="Pos.10 (Año):", font=("Helvetica", 12)).pack()
        self.menu_c10 = tb.OptionMenu(parent, self.var_c10, valor_inicial(posicion_10), *posicion_10.keys())
        self.menu_c10.pack()

        # Pos.11
        tb.Label(parent, text="Pos.11 (Planta):", font=("Helvetica", 12)).pack()
        self.menu_c11 = tb.OptionMenu(parent, self.var_c11, valor_inicial(posicion_11), *posicion_11.keys())
        self.menu_c11.pack()

    def generar_vin(self):
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
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

        # Llamamos a /obtener_secuencial en Flask
        sec = self.obtener_secuencial_desde_servidor(c10)
        if sec == 0:
            return  # se manejó el error en la función

        sec_str = str(sec).zfill(3)
        fixed_12_14 = "098"
        valores = f"{wmi}{c4}{c5}{c6}{c7}{c8}{c10}{c11}{fixed_12_14}{sec_str}"
        pos9 = self.calcular_posicion_9(valores)

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
            self.result_label.config(text=f"VIN/NIV: {vin_completo}", font=("Helvetica", 24, "bold"))
        else:
            self.result_label = tb.Label(self.right_frame, text=f"VIN/NIV: {vin_completo}",
                                         font=("Helvetica", 24, "bold"))
            self.result_label.pack(pady=5)

    def calcular_posicion_9(self, valores):
        # Cálculo módulo 11
        sustituciones = {
            "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
            "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2,
            "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
        }
        for i in range(10):
            sustituciones[str(i)] = i
        suma = sum(sustituciones.get(char, 0) for char in valores)
        resultado_modulo = suma % 11
        return "X" if resultado_modulo == 10 else str(resultado_modulo)

    def ventana_lista_vins(self):
        if not self.verificar_licencia():
            return
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

        vins = self.ver_vins_en_flask()
        vins_window = tb.Toplevel(self.master)
        vins_window.title("VINs Generados")
        vins_window.geometry("500x400")

        canvas = tb.Canvas(vins_window)
        scrollbar = tb.Scrollbar(vins_window, orient="vertical", command=canvas.yview)

        scroll_frame = tb.Frame(canvas)
        scroll_frame.bind("<Configure>",
                          lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        texto_vins = ""
        for vin in vins:
            vin_completo = vin.get("vin_completo", "VIN no disponible")
            fecha_crea = vin.get("created_at", "")
            texto_vins += f"VIN Completo: {vin_completo}\nCreado: {fecha_crea}\n" + ("-"*40 + "\n")

        lbl_text = tb.Label(scroll_frame, text=texto_vins,
                            justify="left", font=("Helvetica", 12, "bold"))
        lbl_text.pack(pady=10)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.mostrar_ventana_inicio()


if __name__ == "__main__":
    # Crea una ventana con ttkbootstrap, aplicando un tema moderno
    app_tk = tb.Window(themename="sandstone")
    app_tk.title("VIN Builder - ttkbootstrap Edition")
    # Instancia nuestra app
    VINBuilderApp(app_tk)
    app_tk.mainloop()
