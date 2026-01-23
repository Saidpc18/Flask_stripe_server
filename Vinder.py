# Vinder.py — Cliente (PRODUCCIÓN) actualizado + SINCRONIZACIÓN DE VINs
# Incluye:
# - Cola local de VINs pendientes (AppData/Local/Vinder/pending_vins.json)
# - Si falla /guardar_vin: NO se pierde el VIN (se copia al portapapeles + se guarda en pendientes)
# - Botón "Sincronizar VINs pendientes (N)" para reintentar subirlos al servidor
# - Auto-sync silencioso al iniciar sesión (si hay pendientes)

import os
import sys
import logging
import json
import threading
import webbrowser
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk

# ====== TUFUP (CLIENT-SIDE) ======
try:
    from tufup.client import Client as TufupClient
except Exception:
    TufupClient = None  # si no está instalado, mostraremos error claro

# Toast (opcional)
try:
    from ttkbootstrap.toast import ToastNotification
except Exception:
    ToastNotification = None


# ============================
# CONFIGURACIÓN DE LOGGING
# ============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ============================
# CONFIG UPDATER (GITHUB PAGES)
# ============================
APP_NAME = "Vinder"
APP_VERSION = "0.0.0"  # <-- CAMBIA ESTO al generar releases (ej: "0.0.7")

METADATA_BASE_URL = "https://saidpc18.github.io/Vinder-updates/metadata/"
TARGET_BASE_URL = "https://saidpc18.github.io/Vinder-updates/targets/"

# ============================
# BACKEND API (RAILWAY)
# ============================
DEFAULT_API_BASE = "https://flaskstripeserver-production.up.railway.app"

# PRO: en el .exe (frozen) IGNORA variables de entorno para evitar errores.
# En dev (no frozen) sí permite override con VINDER_API_BASE.
if getattr(sys, "frozen", False):
    API_BASE = DEFAULT_API_BASE.rstrip("/")
else:
    API_BASE = (os.getenv("VINDER_API_BASE") or DEFAULT_API_BASE).rstrip("/")

logger.info(f"[CONFIG] API_BASE={API_BASE}")

# En producción normalmente NO registras desde el cliente
ALLOW_CLIENT_REGISTER = os.getenv("VINDER_ALLOW_REGISTER", "0").strip() == "1"

# Modo de pago visible en UI: "stripe" | "transfer" | "both"
PAYMENT_MODE = os.getenv("VINDER_PAYMENT_MODE", "both").strip().lower()
if PAYMENT_MODE not in ("stripe", "transfer", "both"):
    PAYMENT_MODE = "stripe"

# HTTP tuning
HTTP_TIMEOUT = float(os.getenv("VINDER_HTTP_TIMEOUT", "25"))
HTTP_VERIFY_SSL = os.getenv("VINDER_HTTP_VERIFY_SSL", "1").strip().lower() in ("1", "true", "yes")


# ============================
# UTILIDADES DE RUTAS / RECURSOS
# ============================
def resource_path(relative_name: str) -> str:
    """
    Devuelve una ruta absoluta a un recurso.
    - En dev: junto a este archivo.
    - En PyInstaller: dentro de _MEIPASS o junto al ejecutable según el caso.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    base_dir = meipass if meipass else os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, relative_name)


def app_install_dir() -> str:
    """
    Directorio donde está instalada la app.
    - En modo frozen: carpeta del .exe
    - En dev: carpeta del Vinder.py
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def app_data_dir() -> str:
    """
    Carpeta estable en AppData Local para guardar settings/cola (NO se borra con updates).
    """
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = os.path.join(os.path.expanduser("~"), "AppData", "Local")
    d = os.path.join(base, APP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def tuf_cache_dir() -> str:
    """
    Carpeta de cache del updater en AppData Local.
    """
    return os.path.join(app_data_dir(), "tufup")


# ============================
# COLA LOCAL DE VINs (pendientes)
# ============================
def pending_vins_path() -> str:
    return os.path.join(app_data_dir(), "pending_vins.json")


def _atomic_write_json(path: str, data) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ============================
# CLIENTES (CONFIG EXTERNO)
# ============================
def clients_dir() -> str:
    # Carpeta externa junto al Vinder.py o junto al exe (en producción)
    return os.path.join(app_install_dir(), "clients")


def list_clients() -> list[dict]:
    folder = clients_dir()
    if not os.path.isdir(folder):
        return []
    out: list[dict] = []
    for fn in os.listdir(folder):
        if fn.lower().endswith(".json"):
            path = os.path.join(folder, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                # Validación mínima
                if "client_id" in cfg and "catalogs" in cfg:
                    out.append(cfg)
                else:
                    logger.warning(f"Cliente inválido (faltan claves) en: {path}")
            except Exception as e:
                logger.warning(f"No pude leer cliente {path}: {e}")
    out.sort(key=lambda c: c.get("display_name", c.get("client_id", "")))
    return out


def load_client_by_id(client_id: str) -> dict:
    for cfg in list_clients():
        if cfg.get("client_id") == client_id:
            return cfg
    raise KeyError(f"Cliente no encontrado: {client_id}. Asegúrate de tener clients/{client_id}.json")


def settings_path() -> str:
    return os.path.join(app_data_dir(), "settings.json")


def load_settings() -> dict:
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(d: dict) -> None:
    with open(settings_path(), "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


# ============================
# TUFUP BOOTSTRAP
# ============================
def ensure_root_json_in_cache() -> str:
    """
    Copia root.json desde el directorio de la app al cache (si no existe).
    Devuelve la ruta al root.json en cache.
    """
    cache = tuf_cache_dir()
    metadata_dir = os.path.join(cache, "metadata")
    os.makedirs(metadata_dir, exist_ok=True)

    dst_root = os.path.join(metadata_dir, "root.json")
    if os.path.exists(dst_root):
        return dst_root

    src_root_candidates = [
        resource_path("root.json"),                  # dentro de PyInstaller (_MEIPASS) si lo empaquetas
        os.path.join(app_install_dir(), "root.json") # junto al .exe (recomendado para producción)
    ]

    src_root = None
    for cand in src_root_candidates:
        if os.path.exists(cand):
            src_root = cand
            break

    if not src_root:
        raise FileNotFoundError(
            "No se encontró root.json.\n\n"
            "PRODUCCIÓN: coloca root.json junto al .exe:\n"
            f"  {os.path.join(app_install_dir(), 'root.json')}\n\n"
            "DEV: coloca root.json junto a Vinder.py:\n"
            f"  {resource_path('root.json')}"
        )

    with open(src_root, "rb") as fsrc, open(dst_root, "wb") as fdst:
        fdst.write(fsrc.read())

    return dst_root


def make_tufup_client() -> "TufupClient":
    """
    Crea el cliente de tufup (lado usuario).
    """
    if TufupClient is None:
        raise RuntimeError("tufup no está instalado. Instala con: pip install tufup")

    cache = tuf_cache_dir()
    metadata_dir = os.path.join(cache, "metadata")
    target_dir = os.path.join(cache, "targets")
    extract_dir = os.path.join(cache, "extract")
    os.makedirs(metadata_dir, exist_ok=True)
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(extract_dir, exist_ok=True)

    ensure_root_json_in_cache()

    return TufupClient(
        app_name=APP_NAME,
        app_install_dir=app_install_dir(),
        current_version=APP_VERSION,
        metadata_dir=metadata_dir,
        metadata_base_url=METADATA_BASE_URL,
        target_dir=target_dir,
        target_base_url=TARGET_BASE_URL,
        extract_dir=extract_dir,
    )


# ============================
# FUNCIONES PARA ICONO / UI
# ============================
def set_icon(window, logo_small=None):
    try:
        if logo_small is not None:
            window.iconphoto(False, logo_small)
        else:
            icon_path = resource_path("Vinder_logo.ico")
            if os.path.exists(icon_path):
                window.iconbitmap(icon_path)
    except Exception as e:
        logger.info(f"No se pudo configurar el icono: {e}")


def center_window(win, w=420, h=260):
    try:
        win.update_idletasks()
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x = int((sw - w) / 2)
        y = int((sh - h) / 2)
        win.geometry(f"{w}x{h}+{x}+{y}")
    except Exception:
        pass


# ============================
# CLASE DE LA APLICACIÓN GUI
# ============================
class VinderApp:
    def __init__(self, master: tb.Window):
        self.master = master
        self.master.title("Vinder")

        # ====== logo / icon ======
        self.logo_photo_small = None
        self.logo_photo_large = None
        self.load_logo()
        set_icon(self.master, self.logo_photo_small)

        # ====== estilo ventana ======
        self.master.minsize(1100, 700)
        try:
            self.master.state("zoomed")
        except Exception:
            pass

        # ====== estado UI ======
        self.status_var = tb.StringVar(value="Listo")
        self.vin_var = tb.StringVar(value="")
        self.last_conversion_details = ""

        # ====== auth/session ======
        self.usuario_actual: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.client_id: Optional[str] = None

        # ====== requests session (retries) ======
        self.http = self._make_http_session()

        # ====== cliente/catálogos ======
        self.clients = list_clients()
        if not self.clients:
            messagebox.showerror(
                "Error",
                "No se encontró la carpeta 'clients' o no hay clientes válidos.\n\n"
                f"Ruta esperada:\n{clients_dir()}\n\n"
                "Ejemplo:\nclients/jm.json",
            )
            self.master.destroy()
            return

        self.client_cfg = None
        self.catalogs: dict = {}
        self.fixed_12_14 = "098"

        # Variables de estado (catálogos)
        self.var_wmi = tb.StringVar(value="")
        self.var_c4 = tb.StringVar()
        self.var_c5 = tb.StringVar()
        self.var_c6 = tb.StringVar()
        self.var_c7 = tb.StringVar()
        self.var_c8 = tb.StringVar()
        self.var_c10 = tb.StringVar()
        self.var_c11 = tb.StringVar()

        # UI references
        self.btn_generate = None
        self.btn_sync = None

        # Frame principal
        self.main_frame = tb.Frame(self.master, padding=0)
        self.main_frame.pack(fill="both", expand=True)

        # Menú
        self._build_menubar()

        self.mostrar_ventana_inicio()

    # ----------------------------
    # HTTP robusto
    # ----------------------------
    def _make_http_session(self) -> requests.Session:
        s = requests.Session()
        s.verify = HTTP_VERIFY_SSL
        s.headers.update({
            "User-Agent": f"Vinder/{APP_VERSION} (+desktop)",
            "Accept": "application/json, text/plain, */*",
        })

        retry = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.6,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=("GET", "POST", "PUT", "PATCH", "DELETE"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        return s

    def auth_headers(self) -> dict:
        if not self.auth_token:
            return {}
        return {"Authorization": f"Bearer {self.auth_token}"}

    def _safe_json(self, resp: requests.Response) -> dict:
        try:
            return resp.json()
        except Exception:
            return {}

    def _handle_unauthorized(self, resp: requests.Response) -> bool:
        if resp.status_code == 401:
            err = self._safe_json(resp).get("error", "Sesión expirada o no autorizada")
            self.master.after(0, lambda: messagebox.showerror("Sesión expirada", err))
            self.master.after(0, self.cerrar_sesion)
            return True
        return False

    def _req(self, method: str, path: str, *, headers=None, json_body=None, timeout=None) -> requests.Response:
        url = f"{API_BASE}{path}"
        h = {}
        if headers:
            h.update(headers)
        t = timeout if timeout is not None else HTTP_TIMEOUT
        return self.http.request(method, url, headers=h, json=json_body, timeout=t)

    # ----------------------------
    # Cola local VINs pendientes
    # ----------------------------
    def _load_pending_vins(self) -> list[str]:
        path = pending_vins_path()
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return []
            out = []
            for x in data:
                s = str(x).strip().upper()
                if s:
                    out.append(s)
            # dedup manteniendo orden
            seen = set()
            dedup = []
            for v in out:
                if v not in seen:
                    seen.add(v)
                    dedup.append(v)
            return dedup
        except Exception:
            return []

    def _save_pending_vins(self, vins: list[str]) -> None:
        # normaliza + dedup
        seen = set()
        out = []
        for v in vins:
            v = (v or "").strip().upper()
            if not v:
                continue
            if v in seen:
                continue
            seen.add(v)
            out.append(v)
        try:
            _atomic_write_json(pending_vins_path(), out)
        except Exception:
            try:
                with open(pending_vins_path(), "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    def _queue_pending_vin(self, vin: str) -> None:
        vin = (vin or "").strip().upper()
        if not vin:
            return
        pending = self._load_pending_vins()
        pending.append(vin)
        self._save_pending_vins(pending)

    def pending_vins_count(self) -> int:
        return len(self._load_pending_vins())

    def _refresh_sync_button(self):
        if self.btn_sync is not None:
            try:
                self.btn_sync.configure(text=f"Sincronizar VINs pendientes ({self.pending_vins_count()})")
            except Exception:
                pass

    def sync_pending_vins(self, show_ui: bool = True) -> None:
        """
        Reintenta guardar VINs pendientes en el servidor.
        - NO borra localmente un VIN hasta que el servidor responda OK.
        - Si token expira (401), se detiene.
        """
        pending = self._load_pending_vins()
        if not pending:
            if show_ui:
                self.master.after(0, lambda: messagebox.showinfo("Sincronizar", "No hay VINs pendientes."))
            self.master.after(0, self._refresh_sync_button)
            return

        if not self.auth_token:
            if show_ui:
                self.master.after(0, lambda: messagebox.showerror("Error", "Inicia sesión para sincronizar VINs."))
            return

        ok = 0
        still: list[str] = []

        for vin in pending:
            try:
                resp = self._req(
                    "POST",
                    "/guardar_vin",
                    headers=self.auth_headers(),
                    json_body={"vin_completo": vin},
                    timeout=20,
                )

                if self._handle_unauthorized(resp):
                    # deja vin actual y el resto como pendientes
                    still.append(vin)
                    idx = pending.index(vin)
                    still.extend(pending[idx + 1 :])
                    break

                if resp.status_code == 200:
                    ok += 1
                else:
                    still.append(vin)

            except Exception:
                still.append(vin)

        self._save_pending_vins(still)

        def finish_ui():
            self._refresh_sync_button()
            if show_ui:
                messagebox.showinfo("Sincronizar", f"Sincronizados: {ok}\nPendientes: {len(still)}")
            # status bar
            if len(still) > 0:
                self.status_var.set(f"Sincronización completa. Pendientes: {len(still)}")
            else:
                self.status_var.set("Sincronización completa. No hay pendientes.")

        self.master.after(0, finish_ui)

    def sync_pending_vins_async(self, show_ui: bool = True) -> None:
        def worker():
            try:
                self.sync_pending_vins(show_ui=show_ui)
            except Exception as e:
                if show_ui:
                    self.master.after(0, lambda: messagebox.showerror("Error", f"No se pudo sincronizar: {e}"))
        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------
    # Helpers UI
    # ----------------------------
    def _toast(self, msg: str, bootstyle="info"):
        self.status_var.set(msg)
        if ToastNotification is None:
            return
        try:
            ToastNotification(
                title="Vinder",
                message=msg,
                duration=2000,
                bootstyle=bootstyle,
            ).show_toast()
        except Exception:
            pass

    def _copy_to_clipboard(self, text: str):
        t = (text or "").strip()
        if not t:
            self._toast("No hay datos para copiar", bootstyle="warning")
            return
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(t)
            self._toast("Copiado al portapapeles", bootstyle="success")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo copiar: {e}")

    def _build_menubar(self):
        menubar = tb.Menu(self.master)

        menu_view = tb.Menu(menubar, tearoff=0)
        themes = ["flatly", "litera", "cosmo", "minty", "sandstone", "darkly", "superhero"]
        for t in themes:
            menu_view.add_command(label=t, command=lambda theme=t: self._set_theme(theme))
        menubar.add_cascade(label="Tema", menu=menu_view)

        menu_help = tb.Menu(menubar, tearoff=0)
        menu_help.add_command(label="Acerca de…", command=self._about_dialog)
        menubar.add_cascade(label="Ayuda", menu=menu_help)

        self.master.config(menu=menubar)

    def _set_theme(self, theme: str):
        try:
            self.master.style.theme_use(theme)
            s = load_settings()
            s["theme"] = theme
            save_settings(s)
            self._toast(f"Tema: {theme}", bootstyle="info")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cambiar tema: {e}")

    def _about_dialog(self):
        messagebox.showinfo(
            "Vinder",
            f"Vinder\n\nVersión: {APP_VERSION}\nAPI: {API_BASE}\n\n(c) Vinder",
        )

    # ----------------------------
    # Logo
    # ----------------------------
    def load_logo(self):
        try:
            logo_path = resource_path("Vinder_logo.ico")
            original_logo = Image.open(logo_path)

            self.logo_small = original_logo.resize((32, 32), Image.Resampling.LANCZOS)
            self.logo_photo_small = ImageTk.PhotoImage(self.logo_small)

            self.logo_large = original_logo.resize((128, 128), Image.Resampling.LANCZOS)
            self.logo_photo_large = ImageTk.PhotoImage(self.logo_large)
        except Exception as e:
            logger.info(f"Error al cargar el logo Vinder_logo.ico: {e}")
            self.logo_photo_small = None
            self.logo_photo_large = None

    # ----------------------------
    # Cliente / catálogos
    # ----------------------------
    def apply_client(self, client_id: str):
        cfg = load_client_by_id(client_id)
        catalogs = cfg.get("catalogs", {})
        defaults = cfg.get("defaults", {})

        self.var_wmi.set((defaults.get("wmi") or self.var_wmi.get() or "").upper()[:3])
        self.fixed_12_14 = defaults.get("fixed_12_14", "098")

        required = ["posicion_4", "posicion_5", "posicion_6", "posicion_7", "posicion_8", "posicion_10", "posicion_11"]
        missing = [k for k in required if k not in catalogs or not isinstance(catalogs[k], dict) or not catalogs[k]]
        if missing:
            raise ValueError(f"El cliente '{client_id}' no trae catálogos válidos: {missing}")

        self.client_cfg = cfg
        self.client_id = cfg.get("client_id")
        self.catalogs = catalogs

        logger.info(f"[CLIENT] Cliente activo: {self.client_id} ({cfg.get('display_name')})")

    # ----------------------------
    # ACTUALIZACIONES (TUFUP CLIENT)
    # ----------------------------
    def check_for_updates(self):
        progress_window = tb.Toplevel(self.master)
        progress_window.title("Actualizaciones")
        progress_window.resizable(False, False)
        set_icon(progress_window, self.logo_photo_small)
        center_window(progress_window, 420, 160)
        progress_window.transient(self.master)
        progress_window.grab_set()

        tb.Label(progress_window, text="Buscando actualizaciones...", font=("Segoe UI", 11)).pack(pady=(14, 8))

        bar = tb.Progressbar(progress_window, mode="indeterminate")
        bar.pack(pady=8, padx=24, fill="x")
        bar.start(10)

        def worker():
            try:
                client = make_tufup_client()
                info = client.check_for_updates()
                logger.info(f"[UPDATER] check_for_updates() => {info!r}")

                has_update = info is not None and info is not False
                target_path = None
                new_version = None

                # tolerante a distintas versiones de tufup
                if hasattr(info, "target_path"):
                    target_path = getattr(info, "target_path", None)
                if hasattr(info, "new_version"):
                    new_version = getattr(info, "new_version", None)

                if isinstance(info, dict):
                    has_update = bool(info.get("available", info.get("new_version") or info.get("target_path")))
                    new_version = info.get("new_version") or new_version
                    target_path = info.get("target_path") or target_path
                elif isinstance(info, str):
                    has_update = True
                    new_version = info

                self.master.after(0, bar.stop)
                self.master.after(0, progress_window.destroy)

                if not has_update:
                    self.master.after(0, lambda: messagebox.showinfo("Actualización", "No hay actualizaciones disponibles."))
                    return

                msg = "Hay una nueva actualización disponible."
                if new_version:
                    msg += f"\n\nNueva versión: {new_version}"
                if target_path:
                    msg += f"\nPaquete: {target_path}"
                msg += f"\nTu versión: {APP_VERSION}"
                msg += "\n\n¿Deseas descargar e instalar ahora?"

                def ask_and_apply():
                    if not messagebox.askyesno("Actualización disponible", msg):
                        return

                    pw2 = tb.Toplevel(self.master)
                    pw2.title("Actualizando...")
                    pw2.resizable(False, False)
                    set_icon(pw2, self.logo_photo_small)
                    center_window(pw2, 420, 160)
                    pw2.transient(self.master)
                    pw2.grab_set()

                    tb.Label(pw2, text="Descargando y aplicando actualización...", font=("Segoe UI", 11)).pack(pady=(14, 8))
                    bar2 = tb.Progressbar(pw2, mode="indeterminate")
                    bar2.pack(pady=8, padx=24, fill="x")
                    bar2.start(10)

                    def do_apply():
                        try:
                            # distintas firmas
                            try:
                                client.download_and_apply_update(info)
                            except TypeError:
                                client.download_and_apply_update()

                            self.master.after(0, bar2.stop)
                            self.master.after(0, pw2.destroy)
                            self.master.after(0, lambda: messagebox.showinfo("Actualización", "Actualización aplicada.\n\nCierra y vuelve a abrir la aplicación."))
                        except Exception as e:
                            self.master.after(0, bar2.stop)
                            self.master.after(0, pw2.destroy)
                            self.master.after(0, lambda: messagebox.showerror("Error", f"Error aplicando actualización: {e}"))

                    threading.Thread(target=do_apply, daemon=True).start()

                self.master.after(0, ask_and_apply)

            except Exception as e:
                self.master.after(0, bar.stop)
                self.master.after(0, progress_window.destroy)
                self.master.after(0, lambda: messagebox.showerror("Error", f"No se pudo verificar actualizaciones:\n{e}"))

        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------
    # LICENCIA (usa /me)
    # ----------------------------
    def verificar_licencia(self, show_ui: bool = True) -> bool:
        if not self.auth_token:
            if show_ui:
                messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return False
        try:
            resp = self._req("GET", "/me", headers=self.auth_headers(), timeout=20)
            if self._handle_unauthorized(resp):
                return False
            if resp.status_code != 200:
                err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                if show_ui:
                    messagebox.showerror("Error", f"No se pudo consultar estado de licencia: {err}")
                return False

            data = self._safe_json(resp) or {}
            active = bool(data.get("license_active"))
            if active:
                return True

            if show_ui:
                exp = data.get("license_expiration")
                msg = "Licencia requerida o expirada."
                if exp:
                    msg += f"\n\nExpiración: {exp}"
                messagebox.showerror("Suscripción requerida", msg)
            return False

        except requests.RequestException as e:
            if show_ui:
                messagebox.showerror("Error", f"No se pudo verificar la licencia: {e}")
            return False

    # ----------------------------
    # PAGO (Stripe) — requiere Bearer token
    # ----------------------------
    def iniciar_pago_stripe(self):
        if not self.usuario_actual or not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return
        try:
            resp = self._req("POST", "/create-checkout-session", headers=self.auth_headers(), json_body={}, timeout=30)
            if self._handle_unauthorized(resp):
                return

            if resp.status_code == 200:
                data = self._safe_json(resp)
                url_pago = (data.get("url") or "").strip()
                if url_pago:
                    webbrowser.open(url_pago)
                    messagebox.showinfo("Pago Iniciado", "Se abrió la página de pago en tu navegador.")
                else:
                    messagebox.showerror("Error", "No se recibió una URL válida del servidor.")
            else:
                err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo iniciar el proceso de pago: {err}")

        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    # ----------------------------
    # TRANSFERENCIA (flujo producción)
    # - /transfer/create-order devuelve 200/201 con order + payment
    # - opcional: submit tracking_key (/transfer/submit)
    # ----------------------------
    def iniciar_transferencia(self):
        if not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return

        try:
            resp = self._req("POST", "/transfer/create-order", headers=self.auth_headers(), json_body={}, timeout=25)
            if self._handle_unauthorized(resp):
                return

            data = self._safe_json(resp) or {}

            if resp.status_code == 404:
                messagebox.showinfo("Transferencia", "El servidor no tiene habilitado el flujo de transferencia.")
                return

            if resp.status_code not in (200, 201):
                err = data.get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo crear la orden de transferencia: {err}")
                return

            order = data.get("order") or {}
            pay = data.get("payment") or {}

            reference = (pay.get("reference") or order.get("reference") or "").strip()
            amount_mxn = str(pay.get("amount_mxn") or order.get("amount_mxn") or "").strip()
            expires_at = (order.get("expires_at") or "").strip()

            bank_name = (pay.get("bank_name") or "").strip()
            beneficiary = (pay.get("beneficiary_name") or "").strip()
            clabe = (pay.get("clabe") or "").strip()
            concept = (pay.get("concept") or reference).strip()

            notes = (data.get("notes") or "").strip()

            self._transfer_order_popup(
                reference=reference,
                amount_mxn=amount_mxn,
                expires_at=expires_at,
                bank_name=bank_name,
                beneficiary=beneficiary,
                clabe=clabe,
                concept=concept,
                notes=notes,
            )

        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def _transfer_order_popup(
        self,
        *,
        reference: str,
        amount_mxn: str,
        expires_at: str,
        bank_name: str,
        beneficiary: str,
        clabe: str,
        concept: str,
        notes: str = "",
    ):
        w = tb.Toplevel(self.master)
        w.title("Pago por Transferencia")
        set_icon(w, self.logo_photo_small)
        center_window(w, 820, 520)
        w.transient(self.master)
        w.grab_set()

        txt = (
            "INSTRUCCIONES DE TRANSFERENCIA\n\n"
            f"Banco: {bank_name or '-'}\n"
            f"Beneficiario: {beneficiary or '-'}\n"
            f"CLABE: {clabe or '-'}\n\n"
            f"Monto (MXN): {amount_mxn or '-'}\n"
            f"Referencia / Concepto: {concept or reference or '-'}\n"
            f"Vence: {expires_at or '-'}\n\n"
            "IMPORTANTE:\n"
            "- Usa EXACTAMENTE la referencia/concepto.\n"
            "- Si tu banco pregunta 'concepto', pega la referencia.\n"
        )
        if notes:
            txt += f"\nNotas:\n- {notes}\n"

        st = ScrolledText(w, wrap="word", font=("Consolas", 11))
        st.pack(fill="both", expand=True, padx=12, pady=12)
        st.insert("end", txt)
        st.configure(state="disabled")

        frm = tb.Frame(w, padding=(12, 0))
        frm.pack(fill="x", pady=(0, 10))

        tb.Button(frm, text="Copiar CLABE", bootstyle="secondary", command=lambda: self._copy_to_clipboard(clabe)).pack(side="left", padx=5)
        tb.Button(frm, text="Copiar Monto", bootstyle="secondary", command=lambda: self._copy_to_clipboard(amount_mxn)).pack(side="left", padx=5)
        tb.Button(frm, text="Copiar Referencia", bootstyle="secondary", command=lambda: self._copy_to_clipboard(concept or reference)).pack(side="left", padx=5)

        submit_box = tb.Labelframe(w, text="Enviar clave de rastreo (opcional)", padding=12, bootstyle="info")
        submit_box.pack(fill="x", padx=12, pady=(0, 12))

        tb.Label(submit_box, text="Clave de rastreo / folio:").pack(anchor="w")
        entry_track = tb.Entry(submit_box, font=("Segoe UI", 11))
        entry_track.pack(fill="x", pady=(4, 8))

        def do_submit():
            tracking_key = entry_track.get().strip()
            if not tracking_key:
                messagebox.showerror("Error", "Escribe tu clave de rastreo.")
                return
            try:
                resp = self._req(
                    "POST",
                    "/transfer/submit",
                    headers=self.auth_headers(),
                    json_body={"reference": reference, "tracking_key": tracking_key},
                    timeout=25,
                )
                if self._handle_unauthorized(resp):
                    return
                data = self._safe_json(resp) or {}
                if resp.status_code == 200:
                    messagebox.showinfo("Enviado", "Comprobante enviado. En espera de aprobación.")
                    w.destroy()
                    return
                err = data.get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo enviar el comprobante: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error de conexión: {e}")

        tb.Button(submit_box, text="Enviar", bootstyle="info", command=do_submit).pack(anchor="e")
        tb.Button(w, text="Cerrar", bootstyle="secondary", command=w.destroy).pack(pady=(0, 12))

    # ----------------------------
    # VINs API
    # ----------------------------
    def guardar_vin_en_flask(self, vin_completo: str, show_ui: bool = True) -> bool:
        if not self.auth_token:
            if show_ui:
                messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return False

        try:
            resp = self._req("POST", "/guardar_vin", headers=self.auth_headers(), json_body={"vin_completo": vin_completo}, timeout=20)
            if self._handle_unauthorized(resp):
                return False
            if resp.status_code == 200:
                return True
            err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
            if show_ui:
                messagebox.showerror("Error", f"No se pudo guardar el VIN: {err}")
            return False
        except requests.RequestException as e:
            if show_ui:
                messagebox.showerror("Error", f"Error al conectarse al servidor: {e}")
            return False

    def ver_vins_en_flask(self):
        if not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return []
        try:
            resp = self._req("GET", "/ver_vins", headers=self.auth_headers(), timeout=20)
            if self._handle_unauthorized(resp):
                return []
            if resp.status_code == 200:
                data = self._safe_json(resp)
                return data.get("vins", [])
            err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
            messagebox.showerror("Error", f"No se pudo obtener VINs: {err}")
            return []
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
            return []

    def obtener_secuencial_desde_servidor(self, year_code, show_ui: bool = True) -> int:
        if not self.auth_token:
            if show_ui:
                messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return 0

        try:
            resp = self._req("POST", "/obtener_secuencial", headers=self.auth_headers(), json_body={"year": year_code}, timeout=20)
            if self._handle_unauthorized(resp):
                return 0
            if resp.status_code == 200:
                data = self._safe_json(resp)
                return int(data.get("secuencial", 0) or 0)
            err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
            if show_ui:
                messagebox.showerror("Error", f"Error al obtener secuencial: {err}")
            return 0
        except requests.RequestException as e:
            if show_ui:
                messagebox.showerror("Error", f"No se pudo conectar a /obtener_secuencial: {e}")
            return 0

    def exportar_vins(self):
        if not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return
        try:
            resp = self._req("GET", "/export_vins", headers=self.auth_headers(), timeout=60)
            if self._handle_unauthorized(resp):
                return
            if resp.status_code == 200:
                filename = filedialog.asksaveasfilename(
                    defaultextension=".xlsx",
                    filetypes=[("Excel files", "*.xlsx")],
                    title="Guardar lista de VINs",
                )
                if filename:
                    with open(filename, "wb") as f:
                        f.write(resp.content)
                    messagebox.showinfo("Éxito", f"Archivo exportado exitosamente: {filename}")
                else:
                    messagebox.showinfo("Exportar VINs", "Exportación cancelada.")
            else:
                err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo exportar los VINs: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

    def eliminar_todos_vins(self):
        if not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Estás seguro que deseas eliminar TODOS los VINs?"):
            return
        try:
            resp = self._req("POST", "/eliminar_todos_vins", headers=self.auth_headers(), json_body={}, timeout=20)
            if self._handle_unauthorized(resp):
                return
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "Todos los VINs han sido eliminados y el secuencial se ha reiniciado.")
            else:
                err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo eliminar todos los VINs: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar al servidor: {e}")

    def eliminar_ultimo_vin(self):
        if not self.auth_token:
            messagebox.showerror("Error", "Sesión inválida. Vuelve a iniciar sesión.")
            return
        if not self.verificar_licencia():
            return
        if not messagebox.askyesno("Confirmación", "¿Estás seguro que deseas eliminar el ÚLTIMO VIN?"):
            return
        try:
            resp = self._req("POST", "/eliminar_ultimo_vin", headers=self.auth_headers(), json_body={}, timeout=20)
            if self._handle_unauthorized(resp):
                return
            if resp.status_code == 200:
                messagebox.showinfo("Éxito", "El último VIN ha sido eliminado y el secuencial se ha actualizado.")
            else:
                err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                messagebox.showerror("Error", f"No se pudo eliminar el último VIN: {err}")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo conectar con el servidor: {e}")

    # ----------------------------
    # VISTAS / NAVEGACIÓN
    # ----------------------------
    def limpiar_main_frame(self):
        for w in self.main_frame.winfo_children():
            w.destroy()

    def mostrar_ventana_inicio(self):
        self.limpiar_main_frame()

        PAD = 24
        root = tb.Frame(self.main_frame, padding=(PAD, PAD))
        root.pack(fill="both", expand=True)

        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        container = tb.Frame(root)
        container.grid(row=0, column=0, sticky="nsew")
        container.columnconfigure(0, weight=1)

        if self.logo_photo_large is not None:
            tb.Label(container, image=self.logo_photo_large).pack(pady=(10, 6))

        tb.Label(container, text="Vinder", font=("Segoe UI", 24, "bold")).pack(pady=(4, 2))
        tb.Label(container, text="Generador de VIN con control de licencia", bootstyle="secondary").pack(pady=(0, 18))

        cards = tb.Frame(container)
        cards.pack()

        card_left = tb.Labelframe(cards, text="Acceso", padding=18, bootstyle="primary")
        card_left.grid(row=0, column=0, padx=10, pady=10, sticky="n")

        tb.Button(card_left, text="Iniciar Sesión", bootstyle="primary", command=self.ventana_iniciar_sesion).pack(
            fill="x", pady=(0, 10)
        )

        if ALLOW_CLIENT_REGISTER:
            tb.Button(card_left, text="Crear Cuenta", bootstyle="outline-primary", command=self.ventana_crear_cuenta).pack(
                fill="x"
            )

        card_right = tb.Labelframe(cards, text="Sistema", padding=18, bootstyle="secondary")
        card_right.grid(row=0, column=1, padx=10, pady=10, sticky="n")

        tb.Label(card_right, text=f"Versión: {APP_VERSION}").pack(anchor="w")
        tb.Label(card_right, text=f"API: {API_BASE}").pack(anchor="w")
        tb.Label(card_right, text=f"Clientes: {len(self.clients)}").pack(anchor="w")
        tb.Label(card_right, text=f"Pendientes (local): {self.pending_vins_count()}").pack(anchor="w")

        tb.Button(card_right, text="Buscar actualizaciones", bootstyle="secondary", command=self.check_for_updates).pack(
            fill="x", pady=(12, 0)
        )

        statusbar = tb.Frame(root, padding=(0, 8))
        statusbar.grid(row=1, column=0, sticky="ew")
        statusbar.columnconfigure(0, weight=1)
        tb.Label(statusbar, textvariable=self.status_var, bootstyle="secondary").grid(row=0, column=0, sticky="w")

    def ventana_crear_cuenta(self):
        self.limpiar_main_frame()

        PAD = 24
        root = tb.Frame(self.main_frame, padding=(PAD, PAD))
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)

        card = tb.Labelframe(root, text="Crear cuenta", padding=18, bootstyle="primary")
        card.grid(row=0, column=0, sticky="n", pady=10)

        if self.logo_photo_small is not None:
            tb.Label(card, image=self.logo_photo_small).grid(row=0, column=0, sticky="w", pady=(0, 10))

        tb.Label(card, text="Usuario").grid(row=1, column=0, sticky="w")
        entry_reg_user = tb.Entry(card, font=("Segoe UI", 12), width=28)
        entry_reg_user.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        tb.Label(card, text="Contraseña").grid(row=3, column=0, sticky="w")
        entry_reg_pass = tb.Entry(card, show="*", font=("Segoe UI", 12), width=28)
        entry_reg_pass.grid(row=4, column=0, sticky="ew", pady=(0, 12))

        def do_register():
            username = entry_reg_user.get().strip()
            password = entry_reg_pass.get().strip()
            if not username or not password:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            try:
                resp = self._req("POST", "/register", json_body={"username": username, "password": password}, timeout=20)
                if resp.status_code == 404:
                    messagebox.showerror("Error", "El backend de producción no tiene /register. Crea usuarios con /admin/create_user.")
                    return
                if resp.status_code == 201:
                    messagebox.showinfo("Éxito", "Cuenta creada exitosamente. Ahora puedes iniciar sesión.")
                    self.mostrar_ventana_inicio()
                else:
                    err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                    messagebox.showerror("Error", f"Registro fallido: {err}")
            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectarse con el servidor: {e}")

        tb.Button(card, text="Registrar", bootstyle="success", command=do_register).grid(row=5, column=0, sticky="ew")
        tb.Button(card, text="Volver", bootstyle="secondary", command=self.mostrar_ventana_inicio).grid(
            row=6, column=0, sticky="ew", pady=(8, 0)
        )

    def ventana_iniciar_sesion(self):
        self.limpiar_main_frame()

        PAD = 24
        root = tb.Frame(self.main_frame, padding=(PAD, PAD))
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)

        card = tb.Labelframe(root, text="Iniciar sesión", padding=18, bootstyle="primary")
        card.grid(row=0, column=0, sticky="n", pady=10)

        if self.logo_photo_small is not None:
            tb.Label(card, image=self.logo_photo_small).grid(row=0, column=0, sticky="w", pady=(0, 10))

        tb.Label(card, text="Usuario").grid(row=1, column=0, sticky="w")
        entry_user = tb.Entry(card, font=("Segoe UI", 12), width=28)
        entry_user.grid(row=2, column=0, sticky="ew", pady=(0, 10))

        tb.Label(card, text="Contraseña").grid(row=3, column=0, sticky="w")
        entry_pass = tb.Entry(card, show="*", font=("Segoe UI", 12), width=28)
        entry_pass.grid(row=4, column=0, sticky="ew", pady=(0, 12))

        def do_login():
            user = entry_user.get().strip()
            pw = entry_pass.get().strip()
            if not user or not pw:
                messagebox.showerror("Error", "Completa todos los campos.")
                return

            try:
                resp = self._req("POST", "/login", json_body={"username": user, "password": pw}, timeout=20)
                if resp.status_code != 200:
                    err = self._safe_json(resp).get("error", f"HTTP {resp.status_code}")
                    messagebox.showerror("Error", f"Login fallido: {err}")
                    return

                data = self._safe_json(resp) or {}
                token = data.get("token")
                client_id = data.get("client_id")

                # Fallback /me por si cambias login algún día
                if token and not client_id:
                    try:
                        me_resp = self._req("GET", "/me", headers={"Authorization": f"Bearer {token}"}, timeout=15)
                        if me_resp.status_code == 200:
                            client_id = (me_resp.json() or {}).get("client_id")
                    except Exception:
                        pass

                if not token or not client_id:
                    messagebox.showerror("Error", "Login OK pero faltó token o client_id en la respuesta.")
                    return

                self.usuario_actual = user
                self.auth_token = token
                self.client_id = client_id

                try:
                    self.apply_client(client_id)
                except Exception as e:
                    messagebox.showerror(
                        "Error",
                        f"Tu usuario está asociado a '{client_id}', pero no existe su archivo en clients.\n\nDetalle: {e}",
                    )
                    self.cerrar_sesion()
                    return

                self._toast(f"Bienvenido, {user}", bootstyle="success")
                self.ventana_principal()

                # Auto-sync silencioso al iniciar sesión (si hay pendientes)
                if self.pending_vins_count() > 0:
                    self.master.after(300, lambda: self.sync_pending_vins_async(show_ui=False))

            except requests.RequestException as e:
                messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")

        tb.Button(card, text="Entrar", bootstyle="primary", command=do_login).grid(row=5, column=0, sticky="ew")
        tb.Button(card, text="Volver", bootstyle="secondary", command=self.mostrar_ventana_inicio).grid(
            row=6, column=0, sticky="ew", pady=(8, 0)
        )

    # ----------------------------
    # PANTALLA PRINCIPAL
    # ----------------------------
    def ventana_principal(self):
        self.limpiar_main_frame()

        PAD = 16
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

        # ===== HEADER =====
        header = tb.Frame(self.main_frame, padding=(PAD, 12))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(2, weight=1)

        if self.logo_photo_small is not None:
            tb.Label(header, image=self.logo_photo_small).grid(row=0, column=0, sticky="w", padx=(0, 10))

        tb.Label(header, text="Vinder", font=("Segoe UI", 16, "bold")).grid(row=0, column=1, sticky="w")

        user_txt = f"Usuario: {self.usuario_actual or '-'}   |   Cliente: {self.client_id or '-'}"
        tb.Label(header, text=user_txt, bootstyle="secondary").grid(row=0, column=2, sticky="e")

        # ===== CONTENIDO =====
        content = tb.Frame(self.main_frame, padding=(PAD, PAD))
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)
        content.rowconfigure(0, weight=1)

        card_left = tb.Labelframe(content, text="Datos del VIN", padding=PAD, bootstyle="primary")
        card_left.grid(row=0, column=0, sticky="nsew", padx=(0, PAD))
        card_left.columnconfigure(1, weight=1)

        card_right = tb.Frame(content)
        card_right.grid(row=0, column=1, sticky="nsew")
        card_right.rowconfigure(1, weight=1)

        card_result = tb.Labelframe(card_right, text="Resultado", padding=PAD, bootstyle="success")
        card_result.grid(row=0, column=0, sticky="ew", pady=(0, PAD))
        card_result.columnconfigure(0, weight=1)

        card_actions = tb.Labelframe(card_right, text="Acciones", padding=PAD, bootstyle="secondary")
        card_actions.grid(row=1, column=0, sticky="nsew")

        tb.Label(card_left, text="WMI (3 caracteres):").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=(0, 8))
        entry_wmi = tb.Entry(card_left, textvariable=self.var_wmi, width=10, font=("Segoe UI", 12))
        entry_wmi.grid(row=0, column=1, sticky="w", pady=(0, 8))
        entry_wmi.bind("<KeyRelease>", lambda e: self.var_wmi.set(self.var_wmi.get().upper()[:3]))

        self.crear_optionmenus(card_left, start_row=1)

        self.vin_var.set("")
        vin_entry = tb.Entry(card_result, textvariable=self.vin_var, font=("Segoe UI", 14, "bold"))
        vin_entry.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        vin_entry.configure(state="readonly")

        tb.Button(
            card_result,
            text="Copiar VIN",
            bootstyle="outline-secondary",
            command=lambda: self._copy_to_clipboard(self.vin_var.get()),
        ).grid(row=1, column=0, sticky="ew")

        tb.Button(
            card_result,
            text="Ver detalle Pos.9",
            bootstyle="outline-secondary",
            command=self._ver_detalle_pos9,
        ).grid(row=2, column=0, sticky="ew", pady=(8, 0))

        self.btn_generate = tb.Button(card_actions, text="Generar VIN", bootstyle="primary", command=self.generar_vin_async)
        self.btn_generate.pack(fill="x", pady=(0, 10))

        # ✅ NUEVO: Sync pendientes (si falla el guardado, aquí lo arreglas)
        self.btn_sync = tb.Button(
            card_actions,
            text=f"Sincronizar VINs pendientes ({self.pending_vins_count()})",
            bootstyle="info",
            command=lambda: self.sync_pending_vins_async(show_ui=True),
        )
        self.btn_sync.pack(fill="x", pady=4)

        if PAYMENT_MODE in ("stripe", "both"):
            tb.Button(card_actions, text="Renovar Licencia (Tarjeta)", bootstyle="success", command=self.iniciar_pago_stripe).pack(fill="x", pady=4)
        if PAYMENT_MODE in ("transfer", "both"):
            tb.Button(card_actions, text="Pagar por Transferencia", bootstyle="success", command=self.iniciar_transferencia).pack(fill="x", pady=4)

        tb.Button(card_actions, text="Ver VINs Generados", bootstyle="info", command=self.ventana_lista_vins).pack(fill="x", pady=4)
        tb.Button(card_actions, text="Exportar VINs a Excel", bootstyle="info", command=self.exportar_vins).pack(fill="x", pady=4)

        tb.Separator(card_actions).pack(fill="x", pady=10)

        tb.Button(card_actions, text="Eliminar TODOS los VINs", bootstyle="warning", command=self.eliminar_todos_vins).pack(fill="x", pady=4)
        tb.Button(card_actions, text="Eliminar ÚLTIMO VIN", bootstyle="warning", command=self.eliminar_ultimo_vin).pack(fill="x", pady=4)

        tb.Separator(card_actions).pack(fill="x", pady=10)

        tb.Button(card_actions, text="Buscar actualizaciones", bootstyle="secondary", command=self.check_for_updates).pack(fill="x", pady=4)
        tb.Button(card_actions, text="Cerrar Sesión", bootstyle="danger", command=self.cerrar_sesion).pack(fill="x", pady=(10, 0))

        statusbar = tb.Frame(self.main_frame, padding=(PAD, 8))
        statusbar.grid(row=2, column=0, sticky="ew")
        statusbar.columnconfigure(0, weight=1)
        tb.Label(statusbar, textvariable=self.status_var, bootstyle="secondary").grid(row=0, column=0, sticky="w")
        tb.Label(statusbar, text=f"Versión {APP_VERSION}", bootstyle="secondary").grid(row=0, column=1, sticky="e")

        self._refresh_sync_button()

    def _ver_detalle_pos9(self):
        if not self.last_conversion_details:
            self._toast("Aún no se ha generado un VIN.", bootstyle="warning")
            return
        w = tb.Toplevel(self.master)
        w.title("Detalle Posición 9")
        set_icon(w, self.logo_photo_small)
        center_window(w, 900, 420)

        st = ScrolledText(w, wrap="word", font=("Consolas", 10))
        st.pack(fill="both", expand=True, padx=10, pady=10)
        st.insert("end", self.last_conversion_details)
        st.configure(state="disabled")

        tb.Button(w, text="Cerrar", bootstyle="secondary", command=w.destroy).pack(pady=(0, 10))

    def crear_optionmenus(self, parent, start_row=0):
        p4 = self.catalogs["posicion_4"]
        p5 = self.catalogs["posicion_5"]
        p6 = self.catalogs["posicion_6"]
        p7 = self.catalogs["posicion_7"]
        p8 = self.catalogs["posicion_8"]
        p10 = self.catalogs["posicion_10"]
        p11 = self.catalogs["posicion_11"]

        def set_default(var: tb.StringVar, d: dict):
            if not var.get():
                var.set(next(iter(d.keys())))

        set_default(self.var_c4, p4)
        set_default(self.var_c5, p5)
        set_default(self.var_c6, p6)
        set_default(self.var_c7, p7)
        set_default(self.var_c8, p8)
        set_default(self.var_c10, p10)
        set_default(self.var_c11, p11)

        def add_combo(r, label, var, values):
            tb.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=(0, 10), pady=6)
            cb = tb.Combobox(parent, textvariable=var, values=list(values), state="readonly")
            cb.grid(row=r, column=1, sticky="ew", pady=6)
            return cb

        row = start_row
        add_combo(row, "Pos.4 (Modelo):", self.var_c4, p4.keys()); row += 1
        add_combo(row, "Pos.5:", self.var_c5, p5.keys()); row += 1
        add_combo(row, "Pos.6:", self.var_c6, p6.keys()); row += 1
        add_combo(row, "Pos.7:", self.var_c7, p7.keys()); row += 1
        add_combo(row, "Pos.8:", self.var_c8, p8.keys()); row += 1
        add_combo(row, "Pos.10 (Año):", self.var_c10, p10.keys()); row += 1
        add_combo(row, "Pos.11 (Planta):", self.var_c11, p11.keys()); row += 1

    # ----------------------------
    # Generación VIN (sin congelar UI) + cola local si falla guardado
    # ----------------------------
    def generar_vin_async(self):
        if self.btn_generate is not None:
            try:
                self.btn_generate.configure(state="disabled")
            except Exception:
                pass

        self.status_var.set("Generando VIN...")

        def worker():
            try:
                ok_lic = self.verificar_licencia(show_ui=False)
                if not ok_lic:
                    self.master.after(0, lambda: messagebox.showerror("Suscripción requerida", "Licencia requerida o expirada."))
                    self.master.after(0, lambda: self.status_var.set("Suscripción requerida."))
                    return

                wmi = self.var_wmi.get().strip().upper()
                p4 = self.catalogs["posicion_4"]
                p5 = self.catalogs["posicion_5"]
                p6 = self.catalogs["posicion_6"]
                p7 = self.catalogs["posicion_7"]
                p8 = self.catalogs["posicion_8"]
                p10 = self.catalogs["posicion_10"]
                p11 = self.catalogs["posicion_11"]

                c4 = p4.get(self.var_c4.get(), "")
                c5 = p5.get(self.var_c5.get(), "")
                c6 = p6.get(self.var_c6.get(), "")
                c7 = p7.get(self.var_c7.get(), "")
                c8 = p8.get(self.var_c8.get(), "")
                c10 = p10.get(self.var_c10.get(), "")
                c11 = p11.get(self.var_c11.get(), "")

                if not (wmi and c4 and c5 and c6 and c7 and c8 and c10 and c11):
                    self.master.after(0, lambda: messagebox.showerror("Error", "Faltan datos en uno de los catálogos."))
                    self.master.after(0, lambda: self.status_var.set("Faltan datos."))
                    return

                sec = self.obtener_secuencial_desde_servidor(c10, show_ui=False)
                if sec == 0:
                    self.master.after(0, lambda: messagebox.showerror("Error", "No se pudo obtener secuencial."))
                    self.master.after(0, lambda: self.status_var.set("Error obteniendo secuencial."))
                    return

                sec_str = str(sec).zfill(3)
                fixed_12_14 = getattr(self, "fixed_12_14", "098")

                valores_sin_pos9 = f"{wmi}{c4}{c5}{c6}{c7}{c8}{c10}{c11}{fixed_12_14}{sec_str}"
                pos9 = self.calcular_posicion_9(valores_sin_pos9)
                vin_completo = f"{wmi}{c4}{c5}{c6}{c7}{c8}{pos9}{c10}{c11}{fixed_12_14}{sec_str}"

                # siempre muestra el VIN generado en UI
                self.master.after(0, lambda: self.vin_var.set(vin_completo))

                saved = self.guardar_vin_en_flask(vin_completo, show_ui=False)

                if not saved:
                    # ✅ NUEVO: no se pierde
                    self._queue_pending_vin(vin_completo)

                    # copia al portapapeles (UI thread)
                    self.master.after(0, lambda: self._copy_to_clipboard(vin_completo))

                    def warn():
                        self._refresh_sync_button()
                        messagebox.showwarning(
                            "VIN pendiente",
                            "Se generó el VIN, pero no se pudo guardar en el servidor.\n\n"
                            "✅ Ya se copió al portapapeles\n"
                            "✅ Se guardó como PENDIENTE para sincronizar después\n\n"
                            "Tip: usa el botón 'Sincronizar VINs pendientes'."
                        )
                        self.status_var.set(f"VIN generado (pendiente). Pendientes: {self.pending_vins_count()}")

                    self.master.after(0, warn)
                    return

                # si guardó ok
                def ok_ui():
                    self._refresh_sync_button()
                    self.status_var.set("VIN generado y guardado.")
                self.master.after(0, ok_ui)

            finally:
                if self.btn_generate is not None:
                    self.master.after(0, lambda: self.btn_generate.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    def calcular_posicion_9(self, valores: str) -> str:
        sustituciones = {
            "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
            "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9, "S": 2,
            "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9
        }
        for i in range(10):
            sustituciones[str(i)] = i

        weights = [8, 7, 6, 5, 4, 3, 2, 10, 9, 8, 7, 6, 5, 4, 3, 2]

        mapping = []
        suma = 0

        for i, char in enumerate(valores):
            valor_num = sustituciones.get(char, 0)
            peso = weights[i]
            valor_ponderado = valor_num * peso
            mapping.append(f"'{char}'→{valor_num} * {peso} = {valor_ponderado}")
            suma += valor_ponderado

        mitad = len(mapping) // 2
        linea1 = "    ".join(mapping[:mitad])
        linea2 = "    ".join(mapping[mitad:])

        conversion_details = (
            "Detalle de la conversión:\n"
            + linea1 + "\n"
            + linea2 + "\n"
            + f"\nSuma total ponderada: {suma}\n"
        )

        resultado_modulo = suma % 11
        conversion_details += f"Módulo 11: {resultado_modulo}\n"

        digito_verificador = "X" if resultado_modulo == 10 else str(resultado_modulo)
        conversion_details += f"Dígito verificador: {digito_verificador}\n"

        self.last_conversion_details = conversion_details
        self.master.after(0, lambda: self.status_var.set(f"Dígito verificador (Pos.9): {digito_verificador}"))

        return digito_verificador

    # ----------------------------
    # VINs lista
    # ----------------------------
    def ventana_lista_vins(self):
        if not self.verificar_licencia():
            return

        vins = self.ver_vins_en_flask()
        vins_window = tb.Toplevel(self.master)
        vins_window.title("VINs Generados")
        set_icon(vins_window, self.logo_photo_small)
        vins_window.geometry("720x520")

        header = tb.Frame(vins_window, padding=12)
        header.pack(fill="x")
        tb.Label(header, text="VINs Generados", font=("Segoe UI", 14, "bold")).pack(side="left")
        tb.Label(header, text=f"Pendientes local: {self.pending_vins_count()}", bootstyle="secondary").pack(side="right")

        st = ScrolledText(vins_window, wrap="none", font=("Consolas", 11), height=20)
        st.pack(fill="both", expand=True, padx=12, pady=8)

        texto_vins = ""
        for vin in vins:
            vin_completo = vin.get("vin_completo", "VIN no disponible")
            fecha_crea = vin.get("created_at", "")
            texto_vins += f"VIN: {vin_completo}\nCreado: {fecha_crea}\n" + ("-" * 60 + "\n")

        st.insert("end", texto_vins)
        st.configure(state="disabled")

        btn_frame = tb.Frame(vins_window, padding=12)
        btn_frame.pack(fill="x")

        tb.Button(btn_frame, text="Sincronizar pendientes", bootstyle="info", command=lambda: self.sync_pending_vins_async(show_ui=True)).pack(side="left", padx=5)
        tb.Button(btn_frame, text="Exportar Excel", bootstyle="info", command=self.exportar_vins).pack(side="left", padx=5)
        tb.Button(btn_frame, text="Eliminar TODOS", bootstyle="danger", command=self.eliminar_todos_vins).pack(side="left", padx=5)
        tb.Button(btn_frame, text="Eliminar ÚLTIMO", bootstyle="danger", command=self.eliminar_ultimo_vin).pack(side="left", padx=5)
        tb.Button(btn_frame, text="Cerrar", bootstyle="secondary", command=vins_window.destroy).pack(side="right", padx=5)

    def cerrar_sesion(self):
        self.usuario_actual = None
        self.auth_token = None
        self.client_id = None
        self.catalogs = {}
        self.client_cfg = None
        self.var_wmi.set("")
        self.vin_var.set("")
        self.last_conversion_details = ""
        self.status_var.set("Listo")
        self.btn_sync = None
        self.mostrar_ventana_inicio()


# ----------------------------
# EJECUCIÓN DEL PROGRAMA
# ----------------------------
if __name__ == "__main__":
    s = load_settings()
    theme = s.get("theme", "sandstone")

    app_tk = tb.Window(themename=theme)
    app_tk.title("Vinder - ttkbootstrap Edition")
    set_icon(app_tk)
    VinderApp(app_tk)
    app_tk.mainloop()
