import os
import sys
import json
import bcrypt  # pip install bcrypt
import tkinter as tk
import requests  # Para enviar solicitudes HTTP al servidor Flask
import webbrowser  # Para abrir la URL de Stripe en el navegador
from tkinter import ttk, messagebox

# ============================
#  UBICACIÓN DE usuarios.json
# ============================
if getattr(sys, 'frozen', False):
    base_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.abspath(".")

usuarios_archivo = os.path.join(base_path, "usuarios.json")

# ============================
#  CARGAR USUARIOS (SI EXISTE)
# ============================
if os.path.exists(usuarios_archivo):
    with open(usuarios_archivo, 'r') as f:
        usuarios = json.load(f)
else:
    usuarios = {}

# ============================
#   CATÁLOGOS
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
    "5´ X 15´ A 20´Pies	": "2",
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
    "1 Eje, Rin 13, 5 birlos, 800, Suspensión de balancin":	"A",
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
    "1301 A 1500" : "4",
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

posicion_12 = {
    "12": "0",
    "13": "9",
    "14": "8"
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

valores_alfabeticos = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5,
    "F": 6, "G": 7, "H": 8, "J": 1, "K": 2,
    "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6,
    "X": 7, "Y": 8, "Z": 9
}

# ============================
#   FUNCIONES DE USUARIOS
# ============================
def guardar_usuarios():
    with open(usuarios_archivo, 'w') as f:
        json.dump(usuarios, f)

def crear_cuenta(usuario, password):
    if usuario in usuarios:
        return False
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    usuarios[usuario] = {
        "password": hashed_pw.decode('utf-8'),
        "secuencial": 1,
        "vins": [],
        "license_expiration": None
    }
    guardar_usuarios()
    return True

def autenticar_usuario(usuario, password):
    if usuario not in usuarios:
        return None
    stored = usuarios[usuario]["password"].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored):
        return usuario
    return None

def renovar_licencia(usuario):
    from datetime import datetime, timedelta
    if usuario not in usuarios:
        return
    ahora = datetime.now()
    expiracion = usuarios[usuario].get("license_expiration")
    if expiracion:
        expiracion = datetime.strptime(expiracion, "%Y-%m-%d")
        if expiracion > ahora:
            nueva_fecha = expiracion + timedelta(days=365)
        else:
            nueva_fecha = ahora + timedelta(days=365)
    else:
        nueva_fecha = ahora + timedelta(days=365)
    usuarios[usuario]["license_expiration"] = nueva_fecha.strftime("%Y-%m-%d")
    guardar_usuarios()

# ============================
#   CÁLCULO DE VIN (POS.9)
# ============================
def convertir_a_valor_numerico(cadena):
    valores = []
    for ch in cadena:
        if ch.isdigit():
            valores.append(int(ch))
        else:
            valores.append(valores_alfabeticos.get(ch.upper(), 0))
    return valores

def multiplicar_por_factores(valores, factores):
    return [v * f for v, f in zip(valores, factores)]

def obtener_posicion_9(val_mult):
    total = sum(val_mult)
    resto = total % 11
    return "X" if resto == 10 else str(resto)

def obtener_posicion_15_16_17(usuario):
    seq = usuarios[usuario]["secuencial"]
    num = f"{seq:03d}"
    usuarios[usuario]["secuencial"] += 1
    guardar_usuarios()
    return num

def calcular_vin(wmi, c4, c5, c6, c7, c8, c10, c11, sec):
    valores = (
        convertir_a_valor_numerico(wmi) +
        convertir_a_valor_numerico(c4) +
        convertir_a_valor_numerico(c5) +
        convertir_a_valor_numerico(c6) +
        convertir_a_valor_numerico(c7) +
        convertir_a_valor_numerico(c8) +
        convertir_a_valor_numerico(c10) +
        convertir_a_valor_numerico(c11) +
        [0] + [9] + [8] +
        convertir_a_valor_numerico(sec)
    )
    factores = [8, 7, 6, 5, 4, 3, 2, 10,
                9, 8, 7, 6, 5, 4, 3, 2]
    mult = multiplicar_por_factores(valores, factores)
    return obtener_posicion_9(mult)

def vin_ya_existe(vin_data, usuario):
    for reg in usuarios[usuario]["vins"]:
        if (
            reg["c4"] == vin_data["c4"] and
            reg["c5"] == vin_data["c5"] and
            reg["c6"] == vin_data["c6"] and
            reg["c7"] == vin_data["c7"] and
            reg["c8"] == vin_data["c8"] and
            reg["c10"] == vin_data["c10"] and
            reg["c11"] == vin_data["c11"]
        ):
            return True
    return False

def guardar_vin(vin_data, usuario):
    usuarios[usuario]["vins"].append(vin_data)
    guardar_usuarios()

# ============================
#   CLASE PRINCIPAL
# ============================
class VINBuilderApp:
    def __init__(self, master):
        self.master = master
        self.master.title("VIN Builder - con usuarios.json en la misma carpeta")

        # Ocupa toda la pantalla (maximizado):
        self.master.state("zoomed")  # o self.master.attributes("-fullscreen", True)

        style = ttk.Style()
        style.theme_use("clam")

        # Frame principal (lo creamos una sola vez)
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(fill="both", expand=True)

        # No creamos left_frame y right_frame aquí porque se destruyen al limpiar;
        # los crearemos *cada vez* que mostremos la ventana principal.
        self.left_frame = None
        self.right_frame = None

        # Variables para OptionMenus
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

    # --------------------------
    # FUNCIONES DE PAGO / LICENCIA
    # --------------------------
    def iniciar_pago(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "Inicia sesión para realizar el pago.")
            return
        try:
            server_url = "http://localhost:5000/create-checkout-session"
            response = requests.post(server_url, json={"usuario": self.usuario_actual})

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

    # --------------------------
    #  VENTANAS DE INICIO / LOGIN
    # --------------------------
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

        ttk.Label(self.main_frame, text="Usuario:").pack()
        entry_user = ttk.Entry(self.main_frame)
        entry_user.pack()

        ttk.Label(self.main_frame, text="Contraseña:").pack()
        entry_pass = ttk.Entry(self.main_frame, show="*")
        entry_pass.pack()

        def do_crear():
            user = entry_user.get().strip()
            pw = entry_pass.get()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return
            if crear_cuenta(user, pw):
                messagebox.showinfo("Éxito", f"Cuenta '{user}' creada.")
                self.mostrar_ventana_inicio()
            else:
                messagebox.showerror("Error", "El usuario ya existe.")

        ttk.Button(self.main_frame, text="Registrar",
                   command=do_crear).pack(pady=10)
        ttk.Button(self.main_frame, text="Volver",
                   command=self.mostrar_ventana_inicio).pack()

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

            autenticado = autenticar_usuario(user, pw)
            if autenticado is None:
                if user not in usuarios:
                    messagebox.showerror("Error", "El usuario no existe.")
                else:
                    messagebox.showerror("Error", "Contraseña incorrecta.")
            else:
                self.usuario_actual = autenticado
                messagebox.showinfo("Éxito", f"Bienvenido, {autenticado}")
                self.ventana_principal()

        ttk.Button(self.main_frame, text="Iniciar Sesión",
                   command=do_login).pack(pady=10)
        ttk.Button(self.main_frame, text="Volver",
                   command=self.mostrar_ventana_inicio).pack()

    # --------------------------
    #  VENTANA PRINCIPAL (POST-LOGIN)
    # --------------------------
    def ventana_principal(self):
        """
        Dividimos la pantalla en dos:
        - Izquierda (self.left_frame): WMI + OptionMenus.
        - Derecha (self.right_frame): Botones de generar VIN, renovar, editar, ver VINs, etc.
        """
        self.limpiar_main_frame()

        # IMPORTANTE: Re-creamos left_frame y right_frame
        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True)

        # Título de Bienvenida
        titulo = ttk.Label(self.main_frame,
                           text=f"Hola, {self.usuario_actual}",
                           font=("Arial", 14, "bold"))
        titulo.pack(pady=10)

        # -- SECCIÓN IZQUIERDA --
        ttk.Label(self.left_frame, text="Generar VIN",
                  font=("Arial", 12, "underline")).pack(pady=5)

        ttk.Label(self.left_frame, text="Código WMI:").pack()
        ttk.Entry(self.left_frame, textvariable=self.var_wmi).pack()

        # OptionMenus en el left_frame
        self.crear_optionmenus(self.left_frame)

        # -- SECCIÓN DERECHA --
        ttk.Button(self.right_frame, text="Generar VIN",
                   command=self.generar_vin).pack(pady=10)

        self.result_label = ttk.Label(self.right_frame, text="VIN/NIV: ")
        self.result_label.pack(pady=5)

        ttk.Button(self.right_frame, text="Renovar Licencia",
                   command=self.iniciar_pago).pack(pady=10)

        ttk.Button(self.right_frame, text="Editar Tablas",
                   command=self.ventana_editar_tablas).pack(pady=5)

        ttk.Button(self.right_frame, text="Ver VINs Generados",
                   command=self.ventana_lista_vins).pack(pady=5)

        ttk.Button(self.right_frame, text="Cerrar Sesión",
                   command=self.cerrar_sesion).pack(pady=10)

    def crear_optionmenus(self, parent):
        """Coloca todos los OptionMenus dentro del frame `parent`."""
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

        sec = obtener_posicion_15_16_17(self.usuario_actual)

        vin_data = {
            "c4": c4, "c5": c5, "c6": c6,
            "c7": c7, "c8": c8, "c10": c10,
            "c11": c11, "secuencial": sec
        }

        # Si quieres impedir que se repitan características, descomenta:
        # if vin_ya_existe(vin_data, self.usuario_actual):
        #     messagebox.showerror("Error", "Ya existe un VIN con estas características.")
        #     return

        pos9 = calcular_vin(wmi, c4, c5, c6, c7, c8, c10, c11, sec)
        vin_str = f"{wmi}{c5}{c4}{c6}{c7}{c8}{pos9}{c10}{c11}083{sec}"

        guardar_vin(vin_data, self.usuario_actual)

        if self.result_label:
            self.result_label.config(text=f"VIN/NIV: {vin_str}")
        messagebox.showinfo("VIN Generado", f"VIN/NIV: {vin_str}")

    def ventana_lista_vins(self):
        if not self.usuario_actual:
            messagebox.showerror("Error", "No hay usuario activo.")
            return

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
        for reg in usuarios[self.usuario_actual]["vins"]:
            c4, c5, c6 = reg["c4"], reg["c5"], reg["c6"]
            c7, c8, c10, c11 = reg["c7"], reg["c8"], reg["c10"], reg["c11"]
            sec = reg["secuencial"]

            pos9 = calcular_vin(self.var_wmi.get().upper(), c4, c5, c6, c7, c8, c10, c11, sec)
            vin_r = f"{self.var_wmi.get().upper()}{c5}{c4}{c6}{c7}{c8}{pos9}{c10}{c11}083{sec}"

            texto_vins += f"VIN: {vin_r}\n"
            texto_vins += f"  - c4: {c4}, c5: {c5}, c6: {c6}, c7: {c7}\n"
            texto_vins += f"  - c8: {c8}, c10: {c10}, c11: {c11}\n"
            texto_vins += f"  - secuencial: {sec}\n"
            texto_vins += "-" * 40 + "\n"

        ttk.Label(scroll_frame, text=texto_vins, justify=tk.LEFT).pack(pady=10)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def ventana_editar_tablas(self):
        edit_win = tk.Toplevel(self.master)
        edit_win.title("Editar Tablas de Asignación")
        edit_win.geometry("400x300")

        ttk.Label(edit_win, text="Selecciona la tabla a editar:").pack(pady=5)
        cat_names = list(catalogos.keys())
        var_cat = tk.StringVar(value=cat_names[0])
        ttk.OptionMenu(edit_win, var_cat, cat_names[0], *cat_names).pack()

        ttk.Label(edit_win, text="Clave (lo que verá el usuario en el menú):").pack(pady=5)
        entry_clave = ttk.Entry(edit_win)
        entry_clave.pack()

        ttk.Label(edit_win, text="Valor (código para VIN):").pack(pady=5)
        entry_valor = ttk.Entry(edit_win)
        entry_valor.pack()

        def do_update():
            cat = var_cat.get()
            dicc_obj = catalogos[cat]
            cl = entry_clave.get().strip()
            vl = entry_valor.get().strip()
            if not cl or not vl:
                messagebox.showerror("Error", "Clave y Valor no pueden estar vacíos.")
                return
            dicc_obj[cl] = vl
            messagebox.showinfo("Éxito", f"Agregado/Actualizado {cl} => {vl} en {cat}.")
            entry_clave.delete(0, 'end')
            entry_valor.delete(0, 'end')
            self.refrescar_menus()

        ttk.Button(edit_win, text="Agregar/Actualizar", command=do_update).pack(pady=10)

    def refrescar_menus(self):
        self.menu_c4["menu"].delete(0, "end")
        for k in posicion_4.keys():
            self.menu_c4["menu"].add_command(label=k, command=lambda val=k: self.var_c4.set(val))
        if posicion_4:
            self.var_c4.set(list(posicion_4.keys())[0])
        else:
            self.var_c4.set("")

        self.menu_c5["menu"].delete(0, "end")
        for k in posicion_5.keys():
            self.menu_c5["menu"].add_command(label=k, command=lambda val=k: self.var_c5.set(val))
        if posicion_5:
            self.var_c5.set(list(posicion_5.keys())[0])
        else:
            self.var_c5.set("")

        self.menu_c6["menu"].delete(0, "end")
        for k in posicion_6.keys():
            self.menu_c6["menu"].add_command(label=k, command=lambda val=k: self.var_c6.set(val))
        if posicion_6:
            self.var_c6.set(list(posicion_6.keys())[0])
        else:
            self.var_c6.set("")

        self.menu_c7["menu"].delete(0, "end")
        for k in posicion_7.keys():
            self.menu_c7["menu"].add_command(label=k, command=lambda val=k: self.var_c7.set(val))
        if posicion_7:
            self.var_c7.set(list(posicion_7.keys())[0])
        else:
            self.var_c7.set("")

        self.menu_c8["menu"].delete(0, "end")
        for k in posicion_8.keys():
            self.menu_c8["menu"].add_command(label=k, command=lambda val=k: self.var_c8.set(val))
        if posicion_8:
            self.var_c8.set(list(posicion_8.keys())[0])
        else:
            self.var_c8.set("")

        self.menu_c10["menu"].delete(0, "end")
        for k in posicion_10.keys():
            self.menu_c10["menu"].add_command(label=k, command=lambda val=k: self.var_c10.set(val))
        if posicion_10:
            self.var_c10.set(list(posicion_10.keys())[0])
        else:
            self.var_c10.set("")

        self.menu_c11["menu"].delete(0, "end")
        for k in posicion_11.keys():
            self.menu_c11["menu"].add_command(label=k, command=lambda val=k: self.var_c11.set(val))
        if posicion_11:
            self.var_c11.set(list(posicion_11.keys())[0])
        else:
            self.var_c11.set("")

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.mostrar_ventana_inicio()

    def limpiar_main_frame(self):
        """Destruimos todos los widgets de self.main_frame."""
        for w in self.main_frame.winfo_children():
            w.destroy()

# ============================
#  PUNTO DE ENTRADA
# ============================
if __name__ == "__main__":
    root = tk.Tk()
    app = VINBuilderApp(root)
    root.mainloop()
