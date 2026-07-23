#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy desktop manager (tkinter)"""

import os, re, subprocess, tempfile, tkinter as tk, ctypes, sys, json, csv, io
from tkinter import ttk, messagebox
from datetime import datetime
from i18n import tr, set_lang, get_lang

# ── command log ─────────────────────────────────────
CMD_LOG = []
CMD_LOG_MAX = 200

def _log_cmd(cmd_str, returncode, stdout, stderr):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "cmd": cmd_str,
        "returncode": returncode,
        "stdout": (stdout or "").strip(),
        "stderr": (stderr or "").strip(),
    }
    CMD_LOG.append(entry)
    if len(CMD_LOG) > CMD_LOG_MAX:
        del CMD_LOG[:len(CMD_LOG) - CMD_LOG_MAX]

# ── netsh logic ──────────────────────────────────────

def _decode(b):
    """Decode subprocess bytes robustly (Chinese Windows uses GBK/CP936)."""
    if not b:
        return ""
    for enc in ("gbk", "cp936", "utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")

def netsh(args):
    """Run netsh command. capture_output primary, shell redirect fallback."""
    cmd_str = "netsh interface portproxy " + " ".join(args)
    try:
        r = subprocess.run(
            ["netsh", "interface", "portproxy"] + args,
            capture_output=True,
        )
        out = _decode(r.stdout)
        err = _decode(r.stderr)
        if r.returncode != 0 and not out and not err:
            return _netsh_shell(args)
        _log_cmd(cmd_str, r.returncode, out, err)
        return r.returncode, out, err
    except Exception:
        return _netsh_shell(args)


def _netsh_shell(args):
    """Fallback: use shell redirect to temp file."""
    try:
        tmp = os.path.join(tempfile.gettempdir(), "netsh_out.txt")
        cmd = " ".join(["netsh", "interface", "portproxy"] + args)
        r = subprocess.run(cmd + " > " + tmp + " 2>&1", shell=True)
        output = ""
        if os.path.exists(tmp):
            try:
                with open(tmp, "rb") as f:
                    output = _decode(f.read())
                os.remove(tmp)
            except Exception:
                pass
        return r.returncode, output, ""
    except Exception as e:
        return 1, "", str(e)


def list_rules():
    rules = []
    pat = re.compile(r"([0-9a-fA-F.:*]+)\s+(\d+)\s+([0-9a-fA-F.:*]+)\s+(\d+)")
    seen = set()
    for rtype in TYPES:
        code, out, err = netsh(["show", rtype])
        if code != 0:
            continue
        for line in out.splitlines():
            m = pat.search(line)
            if not m:
                continue
            la, lp, ca, cp = m.group(1), m.group(2), m.group(3), m.group(4)
            key = (rtype, la, lp)
            if key in seen:
                continue
            seen.add(key)
            rules.append({
                "type": rtype,
                "listenAddress": la, "listenPort": lp,
                "connectAddress": ca, "connectPort": cp,
            })
    return rules


def do_netsh(op, listen_addr, listen_port, connect_addr="", connect_port="", rtype="v4tov4"):
    args = [op, rtype, "listenport=" + str(listen_port or "")]
    if op == "add":
        args.append("connectaddress=" + str(connect_addr or ""))
    if connect_port:
        args.append("connectport=" + str(connect_port))
    if listen_addr and listen_addr != "*":
        args.append("listenaddress=" + str(listen_addr))
    args.append("protocol=tcp")
    code, out, err = netsh(args)
    if code != 0:
        raise RuntimeError(_friendly_error((err or out).strip()))


# ── validation helpers ───────────────────────────────

TYPES = ("v4tov4", "v4tov6", "v6tov4", "v6tov6")

# ---- system tray constants (ctypes Shell_NotifyIcon) ----
try:
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
except Exception:
    user32 = None
    shell32 = None

NIF_ICON = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_TIP = 0x00000004
NIM_ADD = 0x00000000
NIM_DELETE = 0x00000001
NIM_MODIFY = 0x00000002
WM_TRAY_MSG = 0x0400 + 1001
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
GWL_WNDPROC = -4

# Correct 64-bit prototypes for window-proc subclassing (avoids access violations).
try:
    LONG_PTR = ctypes.c_int64
except Exception:
    LONG_PTR = ctypes.c_long

def _proto(name, restype, argtypes):
    try:
        fn = getattr(user32, name)
        fn.restype = restype
        fn.argtypes = argtypes
    except Exception:
        pass

if user32 is not None:
    _proto("GetWindowLongPtrW", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_int])
    _proto("SetWindowLongPtrW", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p])
    _proto("CallWindowProcW", ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p])

class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("hWnd", ctypes.c_void_p),
        ("uID", ctypes.c_uint),
        ("uFlags", ctypes.c_uint),
        ("uCallbackMessage", ctypes.c_uint),
        ("hIcon", ctypes.c_void_p),
        ("szTip", ctypes.c_wchar * 128),
    ]

# ---- startup persistence (registry Run key, zero-dependency) ----
import winreg

APP_NAME = "PortProxyGUI"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

def _self_path():
    """Executable path: frozen EXE when bundled, else this script."""
    if getattr(sys, "frozen", False):
        return '"' + sys.executable + '"'
    return '"' + os.path.abspath(__file__) + '"'

def startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            try:
                winreg.QueryValueEx(k, APP_NAME)
                return True
            except FileNotFoundError:
                return False
    except Exception:
        return False

def set_startup(enable):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                             winreg.KEY_SET_VALUE) as k:
            if enable:
                winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, _self_path())
            else:
                try:
                    winreg.DeleteValue(k, APP_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False

def netsh_adv(args):
    """Run a netsh advfirewall command."""
    cmd_str = "netsh advfirewall " + " ".join(args)
    try:
        r = subprocess.run(["netsh", "advfirewall"] + args, capture_output=True)
        out, err = _decode(r.stdout), _decode(r.stderr)
        _log_cmd(cmd_str, r.returncode, out, err)
        return r.returncode, out, err
    except Exception as e:
        _log_cmd(cmd_str, 1, "", str(e))
        return 1, "", str(e)

def fw_open(port, name):
    """Allow inbound TCP on a port. Best-effort."""
    code, out, err = netsh_adv(["firewall", "add", "rule",
        "name=" + name, "dir=in", "action=allow", "protocol=TCP",
        "localport=" + str(port)])
    return code == 0

def fw_close(port, name):
    """Delete the inbound firewall rule we created. Best-effort."""
    code, out, err = netsh_adv(["firewall", "delete", "rule",
        "name=" + name])
    return code == 0

def import_rules(rules):
    added, skipped = [], []
    for r in rules:
        rtype = str(r.get("type") or "v4tov4").strip().lower()
        if rtype not in TYPES:
            skipped.append(r); continue
        la = str(r.get("listenAddress") or "").strip()
        lp = str(r.get("listenPort") or "").strip()
        ca = str(r.get("connectAddress") or "").strip()
        cp = str(r.get("connectPort") or "").strip()
        ok, _ = validate_port(lp)
        if not ok:
            skipped.append(r); continue
        ok, _ = validate_ip(ca)
        if not ok:
            skipped.append(r); continue
        la_norm = la if la else "0.0.0.0"
        dup = False
        for ex in list_rules():
            exa = "0.0.0.0" if ex["listenAddress"] in ("", "*") else ex["listenAddress"]
            if ex.get("type") == rtype and exa == la_norm and ex["listenPort"] == lp:
                dup = True; break
        if dup:
            skipped.append(r); continue
        try:
            do_netsh("add", la, lp, ca, cp, rtype=rtype)
            added.append(r)
        except Exception:
            skipped.append(r)
    return added, skipped

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None

# ---- CSV parsing -------------------------------------------------------

CSV_HEADER = ["type", "listenaddress", "listenport", "connectaddress", "connectport"]

def parse_csv(text):
    """Parse CSV text into a list of rule dicts. Returns (rules, errors)."""
    rules = []
    errors = []
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return rules, [tr("csv_empty")]
    header = [h.strip().lower() for h in rows[0]]
    if header != CSV_HEADER:
        return rules, [tr("csv_header_err")]
    for i, row in enumerate(rows[1:], start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) < 5:
            errors.append(tr("csv_field_err", i))
            continue
        rules.append({
            "type": row[0].strip(),
            "listenAddress": row[1].strip(),
            "listenPort": row[2].strip(),
            "connectAddress": row[3].strip(),
            "connectPort": row[4].strip(),
        })
    return rules, errors

# ---- WSL detection -----------------------------------------------------

def detect_wsl():
    """Detect WSL2 and return its IP."""
    result = {"available": False, "wsl_ip": "", "host_ip": ""}
    try:
        r = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, timeout=5)
        if r.returncode == 0:
            out = _decode(r.stdout).strip()
            ips = out.split()
            if ips:
                wsl_ip = ips[0]
                result["available"] = True
                result["wsl_ip"] = wsl_ip
                parts = wsl_ip.rsplit(".", 1)
                if len(parts) == 2:
                    result["host_ip"] = parts[0] + ".1"
    except Exception:
        pass
    return result

def relaunch_as_admin():
    """Request UAC elevation and relaunch this script. Returns True if launched."""
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, ""
        else:
            exe = sys.executable
            script = os.path.abspath(__file__)
            params = '"%s"' % script if os.path.exists(script) else ""
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return ret > 32
    except Exception:
        return False


def validate_port(port_str):
    """Validate port number. Returns (True, port_int) or (False, error_msg)."""
    s = port_str.strip()
    if not s:
        return False, tr("msg_port_empty")
    try:
        p = int(s)
    except ValueError:
        return False, tr("msg_port_nan")
    if p < 1 or p > 65535:
        return False, tr("msg_port_range")
    return True, p


def validate_ip(ip_str):
    """Validate IPv4 address. Returns (True, ip) or (False, error_msg)."""
    s = ip_str.strip()
    if s == "*":
        return True, "*"
    if not s:
        return False, tr("msg_addr_empty")
    parts = s.split(".")
    if len(parts) != 4:
        return False, tr("msg_addr_format")
    for part in parts:
        try:
            n = int(part)
        except ValueError:
            return False, tr("msg_addr_nan")
        if n < 0 or n > 255:
            return False, tr("msg_addr_range")
    return True, s


def _friendly_error(raw):
    """Translate netsh error messages."""
    if not raw:
        return tr("err_no_admin")
    if "elevation" in raw.lower() or "提升" in raw:
        return tr("err_need_admin")
    if "already exists" in raw.lower() or "已存在" in raw:
        return tr("err_exists")
    if "not found" in raw.lower() or "找不到" in raw:
        return tr("err_not_found")
    if "parameter" in raw.lower():
        return tr("err_param", raw.strip())
    return raw.strip() or tr("err_generic")


# ── theme system ────────────────────────────────────

THEME_LIGHT = {
    "bg": "#f0f2f5", "card": "#ffffff", "primary": "#2563eb",
    "primary_h": "#1d4ed8", "danger": "#ef4444", "danger_h": "#dc2626",
    "success": "#16a34a", "text": "#1e293b", "text_sec": "#64748b",
    "border": "#e2e8f0", "header_bg": "#1e3a5f", "header_fg": "#ffffff",
    "row_alt": "#f8fafc", "tree_head_bg": "#f1f5f9", "entry_bg": "#ffffff",
}
THEME_DARK = {
    "bg": "#0f172a", "card": "#1e293b", "primary": "#3b82f6",
    "primary_h": "#2563eb", "danger": "#f87171", "danger_h": "#ef4444",
    "success": "#4ade80", "text": "#e2e8f0", "text_sec": "#94a3b8",
    "border": "#334155", "header_bg": "#0f172a", "header_fg": "#f1f5f9",
    "row_alt": "#1a2744", "tree_head_bg": "#1e293b", "entry_bg": "#0f172a",
}

# Registry key for theme/language persistence
SETTINGS_KEY = r"Software\PortProxyGUI"

def _read_setting(name, default=""):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return default

def _write_setting(name, value):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, SETTINGS_KEY, 0,
                             winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(value))
    except Exception:
        pass

FONT_UI      = ("Microsoft YaHei UI", 9)
FONT_MONO    = ("Cascadia Code", 10)
FONT_H1      = ("Microsoft YaHei UI", 18, "bold")
FONT_H2      = ("Microsoft YaHei UI", 11, "bold")
FONT_SMALL   = ("Microsoft YaHei UI", 8)


# ── GUI Application ──────────────────────────────────

class PortProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title(tr("app_title"))
        self.root.geometry("960x620")
        self.root.minsize(720, 440)
        # Load theme preference
        self._dark = _read_setting("Theme", "light") == "dark"
        self.C = THEME_DARK if self._dark else THEME_LIGHT
        # Load language preference
        lang = _read_setting("Language", "zh")
        set_lang(lang)
        self.root.configure(bg=self.C["bg"])
        self._setup_styles()
        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_log_panel()
        self._build_statusbar()
        self._bind_keys()
        self.refresh_rules()
        self.check_admin()
        self._init_tray()
        self._init_startup_toggle()

    def _setup_styles(self):
        C = self.C
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=FONT_UI, background=C["bg"])
        style.configure("TFrame", background=C["bg"])
        style.configure("Card.TFrame", background=C["card"], relief="solid", borderwidth=1)
        style.configure("TLabel", background=C["card"], foreground=C["text"], font=FONT_UI)
        style.configure("Bg.TLabel", background=C["bg"], foreground=C["text"])
        style.configure("Header.TLabel", background=C["header_bg"], foreground=C["header_fg"], font=FONT_H1)
        style.configure("SubHeader.TLabel", background=C["header_bg"], foreground=C["text_sec"], font=FONT_UI)
        style.configure("Section.TLabel", background=C["card"], foreground=C["text"], font=FONT_H2)
        style.configure("Hint.TLabel", background=C["card"], foreground=C["text_sec"], font=FONT_SMALL)
        style.configure("Status.TLabel", background=C["bg"], foreground=C["text_sec"], font=FONT_UI)
        style.configure("StatusOk.TLabel", background=C["bg"], foreground=C["success"], font=FONT_UI)
        style.configure("StatusErr.TLabel", background=C["bg"], foreground=C["danger"], font=FONT_UI)
        style.configure("Count.TLabel", background=C["card"], foreground=C["primary"], font=FONT_H2)
        style.configure("Primary.TButton", background=C["primary"], foreground="#ffffff",
            borderwidth=0, focusthickness=0, padding=(16, 6))
        style.map("Primary.TButton", background=[("active", C["primary_h"]), ("pressed", C["primary_h"])],
            foreground=[("active", "#ffffff")])
        style.configure("Danger.TButton", background=C["card"], foreground=C["danger"],
            borderwidth=1, bordercolor=C["border"], focusthickness=0, padding=(12, 5))
        style.map("Danger.TButton", background=[("active", C["row_alt"]), ("pressed", C["border"])],
            foreground=[("active", C["danger_h"])])
        style.configure("Secondary.TButton", background=C["card"], foreground=C["text_sec"],
            borderwidth=1, bordercolor=C["border"], focusthickness=0, padding=(12, 5))
        style.map("Secondary.TButton", background=[("active", C["bg"]), ("pressed", C["border"])],
            foreground=[("active", C["text"])])
        style.configure("TEntry", fieldbackground=C["entry_bg"], foreground=C["text"],
            borderwidth=1, bordercolor=C["border"], padding=6)
        style.map("TEntry", bordercolor=[("focus", C["primary"])],
            lightcolor=[("focus", C["primary"])], darkcolor=[("focus", C["primary"])])
        style.configure("Treeview", background=C["card"], foreground=C["text"],
            fieldbackground=C["card"], rowheight=32, font=FONT_MONO, borderwidth=0)
        style.configure("Treeview.Heading", background=C["tree_head_bg"], foreground=C["text_sec"],
            font=("Microsoft YaHei UI", 9, "bold"), borderwidth=0, padding=(10, 6))
        style.map("Treeview.Heading", background=[("active", C["border"])])
        style.map("Treeview", background=[("selected", C["primary"])],
            foreground=[("selected", "#ffffff")])
        style.configure("TScrollbar", background=C["bg"], troughcolor=C["bg"], borderwidth=0, arrowsize=14)
        style.configure("TCombobox", fieldbackground=C["entry_bg"], foreground=C["text"],
            background=C["card"], bordercolor=C["border"])
        style.configure("TCheckbutton", background=C["card"], foreground=C["text_sec"], font=FONT_SMALL)

    def _build_menu(self):
        C = self.C
        menubar = tk.Menu(self.root, font=FONT_UI)
        file_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        file_menu.add_command(label=tr("menu_refresh"), command=self.refresh_rules)
        file_menu.add_separator()
        file_menu.add_command(label=tr("menu_exit"), command=self.root.quit)
        menubar.add_cascade(label=tr("menu_file"), menu=file_menu)
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        self._log_visible = tk.BooleanVar(value=False)
        view_menu.add_checkbutton(label=tr("menu_log"), variable=self._log_visible,
            command=self._toggle_log_panel)
        menubar.add_cascade(label=tr("menu_view"), menu=view_menu)
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        tools_menu.add_command(label=tr("menu_wsl"), command=self.detect_wsl_action)
        menubar.add_cascade(label=tr("menu_tools"), menu=tools_menu)
        help_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        help_menu.add_command(label=tr("menu_about"), command=self.show_about)
        menubar.add_cascade(label=tr("menu_help"), menu=help_menu)
        settings_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        self.startup_var = tk.BooleanVar(value=False)
        settings_menu.add_checkbutton(label=tr("menu_startup"), variable=self.startup_var,
            command=self.toggle_startup, font=FONT_UI)
        self._dark_var = tk.BooleanVar(value=self._dark)
        settings_menu.add_checkbutton(label=tr("menu_dark"), variable=self._dark_var,
            command=self.toggle_theme, font=FONT_UI)
        settings_menu.add_command(label=tr("menu_tray"), command=self.hide_to_tray)
        settings_menu.add_separator()
        # Language submenu
        lang_menu = tk.Menu(settings_menu, tearoff=0, font=FONT_UI)
        lang_menu.add_command(label="中文", command=lambda: self._switch_lang("zh"))
        lang_menu.add_command(label="English", command=lambda: self._switch_lang("en"))
        settings_menu.add_cascade(label=tr("menu_lang"), menu=lang_menu)
        settings_menu.add_separator()
        settings_menu.add_command(label=tr("menu_about2"), command=self.show_about)
        menubar.add_cascade(label=tr("menu_settings"), menu=settings_menu)
        self.root.config(menu=menubar)

    def _switch_lang(self, lang):
        set_lang(lang)
        _write_setting("Language", lang)
        # Rebuild UI
        self.toggle_theme()  # reuse rebuild logic

    def _build_header(self):
        C = self.C
        header = tk.Frame(self.root, bg=C["header_bg"], height=72)
        header.pack(fill="x")
        header.pack_propagate(False)
        inner = tk.Frame(header, bg=C["header_bg"])
        inner.pack(fill="both", expand=True, padx=24)
        logo = tk.Frame(inner, bg=C["primary"], width=38, height=38)
        logo.pack(side="left", padx=(0, 14))
        logo.pack_propagate(False)
        tk.Label(logo, text="PP", bg=C["primary"], fg="#ffffff",
                 font=("Segoe UI", 12, "bold")).pack(expand=True)
        title_frame = tk.Frame(inner, bg=C["header_bg"])
        title_frame.pack(side="left")
        tk.Label(title_frame, text=tr("header_title"), bg=C["header_bg"],
                 fg=C["header_fg"], font=FONT_H1).pack(anchor="w")
        tk.Label(title_frame, text=tr("header_subtitle"),
                 bg=C["header_bg"], fg=C["text_sec"], font=FONT_UI).pack(anchor="w")
        refresh_btn = tk.Button(inner, text=tr("refresh"), command=self.refresh_rules,
            bg=C["header_bg"], fg=C["text_sec"], font=FONT_UI,
            bd=0, activebackground=C["border"], activeforeground=C["header_fg"],
            cursor="hand2", padx=14, pady=4)
        refresh_btn.pack(side="right")

        self.admin_label = tk.Label(inner, text="", bg=C["header_bg"], fg=C["text_sec"], font=FONT_UI)
        self.admin_label.pack(side="right", padx=(0, 12))
        self.elevate_btn = tk.Button(inner, text=tr("elevate_btn"), command=self.elevate,
            bg=C["primary"], fg="#ffffff", font=("Microsoft YaHei UI", 9, "bold"),
            bd=0, activebackground=C["primary_h"], activeforeground="#ffffff",
            cursor="hand2", padx=12, pady=5)
        self.elevate_btn.pack(side="right", padx=(0, 12))
        self.elevate_btn.pack_forget()

    def _build_body(self):
        C = self.C
        body = tk.Frame(self.root, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=(16, 0))

        # ── Add Rule card ──
        add_card = tk.Frame(body, bg=C["card"], bd=1, relief="solid",
                            highlightbackground=C["border"], highlightthickness=0)
        add_card.pack(fill="x", pady=(0, 12))
        card_header = tk.Frame(add_card, bg=C["card"])
        card_header.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(card_header, text=tr("add_rule_card"), bg=C["card"],
                 fg=C["text"], font=FONT_H2).pack(side="left")
        form = tk.Frame(add_card, bg=C["card"])
        form.pack(fill="x", padx=20, pady=(0, 16))
        self._field(form, tr("listen_addr"), 0, 0)
        self.listen_addr = self._entry(form, 0, 1, 18, "0.0.0.0")
        self.listen_addr.insert(0, "0.0.0.0")
        tk.Label(form, text=":", bg=C["card"], fg=C["text_sec"],
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=2, padx=(6, 6))
        self.listen_port = self._entry(form, 0, 3, 8, "8080")
        tk.Label(form, text="→", bg=C["card"], fg=C["text_sec"],
                 font=("Segoe UI", 14)).grid(row=0, column=4, padx=(10, 10))
        self._field(form, tr("connect_addr"), 0, 5)
        self.connect_addr = self._entry(form, 0, 6, 18, "192.168.1.100")
        tk.Label(form, text=":", bg=C["card"], fg=C["text_sec"],
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=7, padx=(6, 6))
        self.connect_port = self._entry(form, 0, 8, 8, "80")
        tk.Label(form, text=tr("type_label"), bg=C["card"], fg=C["text_sec"], font=FONT_SMALL).grid(row=0, column=9, padx=(16, 4))
        self.rule_type = tk.StringVar(value="v4tov4")
        type_combo = ttk.Combobox(form, textvariable=self.rule_type, state="readonly",
            values=list(TYPES), width=9, font=FONT_UI)
        type_combo.grid(row=0, column=10, padx=(0, 8))
        self.fw_var = tk.BooleanVar(value=False)
        fw_chk = tk.Checkbutton(form, text=tr("fw_allow"), variable=self.fw_var,
            bg=C["card"], fg=C["text_sec"], font=FONT_SMALL, cursor="hand2",
            activebackground=C["card"], selectcolor=C["card"])
        fw_chk.grid(row=0, column=11, padx=(4, 8))
        self.edit_var = tk.StringVar(value="")
        self.edit_lp = tk.StringVar(value="")
        self.edit_addr = tk.StringVar(value="")
        add_btn = tk.Button(form, text=tr("add_btn"), command=self.add_rule,
            bg=C["primary"], fg="#ffffff", font=("Microsoft YaHei UI", 10, "bold"),
            bd=0, activebackground=C["primary_h"], activeforeground="#ffffff",
            cursor="hand2", padx=20, pady=7)
        add_btn.grid(row=0, column=11, padx=(8, 0))
        tk.Label(add_card, text=tr("form_hint"),
                 bg=C["card"], fg=C["text_sec"], font=FONT_SMALL).pack(
                     anchor="w", padx=20, pady=(0, 12))

        # ── Rules table card ──
        table_card = tk.Frame(body, bg=C["card"], bd=1, relief="solid",
                              highlightbackground=C["border"], highlightthickness=0)
        table_card.pack(fill="both", expand=True)
        table_header = tk.Frame(table_card, bg=C["card"])
        table_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(table_header, text=tr("current_rules"), bg=C["card"],
                 fg=C["text"], font=FONT_H2).pack(side="left")
        self.rule_count_label = tk.Label(table_header, text="",
            bg=C["card"], fg=C["primary"], font=FONT_H2)
        self.rule_count_label.pack(side="left", padx=(8, 0))
        clear_btn = tk.Button(table_header, text=tr("clear_all"), command=self.clear_all,
            bg=C["card"], fg=C["danger"], font=FONT_UI,
            bd=1, relief="solid", activebackground=C["row_alt"],
            activeforeground=C["danger_h"], cursor="hand2", padx=12, pady=3)
        clear_btn.pack(side="right")
        imp_btn = tk.Button(table_header, text=tr("import_btn"), command=self.import_file,
            bg=C["card"], fg=C["primary"], font=FONT_UI,
            bd=1, relief="solid", activebackground=C["row_alt"],
            activeforeground=C["primary_h"], cursor="hand2", padx=12, pady=3)
        imp_btn.pack(side="right", padx=(0, 8))
        exp_btn = tk.Button(table_header, text=tr("export_btn"), command=self.export_json,
            bg=C["card"], fg=C["primary"], font=FONT_UI,
            bd=1, relief="solid", activebackground=C["row_alt"],
            activeforeground=C["primary_h"], cursor="hand2", padx=12, pady=3)
        exp_btn.pack(side="right", padx=(0, 8))
        tree_frame = tk.Frame(table_card, bg=C["card"])
        tree_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        cols = ("listenAddr", "listenPort", "connectAddr", "connectPort", "protocol", "type", "actions")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse", height=10)
        self.tree.heading("listenAddr", text=tr("col_listen_addr"))
        self.tree.heading("listenPort", text=tr("col_listen_port"))
        self.tree.heading("connectAddr", text=tr("col_connect_addr"))
        self.tree.heading("connectPort", text=tr("col_connect_port"))
        self.tree.heading("protocol", text=tr("col_protocol"))
        self.tree.heading("type", text=tr("col_type"))
        self.tree.heading("actions", text=tr("col_actions"))
        self.tree.column("listenAddr", width=180, anchor="w")
        self.tree.column("listenPort", width=100, anchor="center")
        self.tree.column("connectAddr", width=180, anchor="w")
        self.tree.column("connectPort", width=100, anchor="center")
        self.tree.column("protocol", width=70, anchor="center")
        self.tree.column("type", width=80, anchor="center")
        self.tree.column("actions", width=120, anchor="center")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree_menu = tk.Menu(self.root, tearoff=0, bg=C["card"], fg=C["text"],
            font=FONT_UI, activebackground=C["primary"], activeforeground="#ffffff",
            bd=1, relief="solid")
        self.tree_menu.add_command(label=tr("ctx_edit"), command=self.edit_selected)
        self.tree_menu.add_command(label=tr("ctx_delete"), command=self.delete_selected)
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        self.tree.tag_configure("odd", background=C["card"])
        self.tree.tag_configure("even", background=C["row_alt"])

    def _field(self, parent, text, row, col):
        lbl = tk.Label(parent, text=text, bg=self.C["card"], fg=self.C["text_sec"], font=FONT_SMALL)
        lbl.grid(row=row, column=col, sticky="sw", padx=(0, 4), pady=(0, 2))

    def _entry(self, parent, row, col, width, placeholder=""):
        C = self.C
        e = tk.Entry(parent, width=width, font=FONT_MONO, bg=C["entry_bg"],
                     fg=C["text_sec"] if placeholder else C["text"],
                     bd=1, relief="solid",
                     insertbackground=C["text"], selectbackground=C["primary"],
                     selectforeground="#ffffff")
        e.grid(row=row, column=col, sticky="w")
        e.configure(highlightbackground=C["border"], highlightcolor=C["primary"],
                    highlightthickness=1)
        if placeholder:
            e.insert(0, placeholder)
            e.bind("<FocusIn>", lambda evt: self._clear_placeholder(evt, placeholder))
            e.bind("<FocusOut>", lambda evt: self._restore_placeholder(evt, placeholder))
        return e

    def _clear_placeholder(self, event, placeholder):
        w = event.widget
        if w.get() == placeholder:
            w.delete(0, "end")
            w.config(fg=self.C["text"])

    def _restore_placeholder(self, event, placeholder):
        w = event.widget
        if w.get() == "":
            w.insert(0, placeholder)
            w.config(fg=self.C["text_sec"])

    def _build_log_panel(self):
        """Build collapsible log panel (hidden by default)."""
        C = self.C
        self._log_frame = tk.Frame(self.root, bg=C["card"], bd=1, relief="solid")
        log_header = tk.Frame(self._log_frame, bg=C["card"])
        log_header.pack(fill="x", padx=10, pady=(6, 2))
        tk.Label(log_header, text=tr("log_title"), bg=C["card"], fg=C["text"],
                 font=FONT_H2).pack(side="left")
        tk.Button(log_header, text=tr("log_clear"), command=self._clear_log,
            bg=C["card"], fg=C["danger"], font=FONT_SMALL, bd=0,
            cursor="hand2").pack(side="right")
        tk.Button(log_header, text=tr("log_refresh"), command=self._refresh_log,
            bg=C["card"], fg=C["primary"], font=FONT_SMALL, bd=0,
            cursor="hand2").pack(side="right", padx=(0, 8))
        self._log_text = tk.Text(self._log_frame, height=8, font=FONT_MONO,
            bg=C["entry_bg"], fg=C["text"], insertbackground=C["text"],
            bd=0, wrap="word", state="disabled")
        self._log_text.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        # Not packed yet - shown on demand

    def _toggle_log_panel(self):
        if self._log_visible.get():
            self._log_frame.pack(side="bottom", fill="x", padx=20, pady=(0, 4))
            self._refresh_log()
        else:
            self._log_frame.pack_forget()

    def _refresh_log(self):
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        for entry in reversed(CMD_LOG[-100:]):
            line = "[{}] $ {}\n".format(entry["time"], entry["cmd"])
            self._log_text.insert("end", line)
            out = entry["stdout"] or entry["stderr"]
            if out:
                self._log_text.insert("end", "  " + out + "\n")
        self._log_text.config(state="disabled")
        self._log_text.see("end")

    def _clear_log(self):
        CMD_LOG.clear()
        self._refresh_log()

    def _build_statusbar(self):
        self.status = tk.Label(self.root, text=tr("status_ready"), bg=self.C["bg"],
            fg=self.C["text_sec"], font=FONT_UI, anchor="w", padx=20, pady=8)
        self.status.pack(side="bottom", fill="x")

    def _bind_keys(self):
        self.root.protocol("WM_DELETE_WINDOW", self.close_to_tray)
        self.root.bind("<F5>", lambda e: self.refresh_rules())
        self.root.bind("<Control-r>", lambda e: self.refresh_rules())
        self.root.bind("<Control-l>", lambda e: self._toggle_log_shortcut())
        self.root.bind("<Return>", lambda e: self.add_rule())

    def _toggle_log_shortcut(self):
        self._log_visible.set(not self._log_visible.get())
        self._toggle_log_panel()

    def _set_status(self, text, kind="info"):
        C = self.C
        colors = {"info": C["text_sec"], "ok": C["success"], "err": C["danger"]}
        self.status.config(text=text, fg=colors.get(kind, C["text_sec"]))
        self.root.update_idletasks()

    # ── actions ──────────────────────────────────────

    def refresh_rules(self):
        self._set_status(tr("status_refreshing"))
        try:
            rules = list_rules()
            self.tree.delete(*self.tree.get_children())
            for i, r in enumerate(rules):
                tag = "even" if i % 2 == 0 else "odd"
                self.tree.insert("", "end", values=(
                    "  " + r["listenAddress"], r["listenPort"],
                    "  " + r["connectAddress"], r["connectPort"],
                    "TCP", r.get("type", "v4tov4"),
                    tr("actions_hint")
                ), tags=(tag,))
            count = len(rules)
            self.rule_count_label.config(text="({})".format(count) if count else "")
            self._set_status(tr("status_rules_count", count), "ok")
        except Exception as e:
            self._set_status(tr("status_refresh_fail", str(e)), "err")

    def add_rule(self):
        la = self.listen_addr.get().strip()
        lp = self.listen_port.get().strip()
        ca = self.connect_addr.get().strip()
        cp = self.connect_port.get().strip()
        rtype = self.rule_type.get().strip()
        firewall = self.fw_var.get()
        edit_rtype = self.edit_var.get()
        edit_lp = self.edit_lp.get().strip()
        edit_la = self.edit_addr.get().strip()
        if edit_rtype and edit_lp:
            try:
                do_netsh("delete", edit_la if edit_la else "0.0.0.0", edit_lp, rtype=edit_rtype)
            except Exception:
                pass

        # Validate listen port
        ok, result = validate_port(lp)
        if not ok:
            messagebox.showwarning(tr("dlg_port_err"), result, parent=self.root)
            self.listen_port.focus()
            return

        # Validate connect port (if provided)
        if cp:
            ok, result = validate_port(cp)
            if not ok:
                messagebox.showwarning(tr("dlg_port_err"), tr("msg_target_prefix") + result, parent=self.root)
                self.connect_port.focus()
                return

        # Validate IP addresses
        if la:
            ok, result = validate_ip(la)
            if not ok:
                messagebox.showwarning(tr("dlg_addr_err"), tr("msg_listen_prefix") + result, parent=self.root)
                self.listen_addr.focus()
                return
        if not ca:
            messagebox.showwarning(tr("dlg_hint"), tr("msg_input_target"), parent=self.root)
            self.connect_addr.focus()
            return
        ok, result = validate_ip(ca)
        if not ok:
            messagebox.showwarning(tr("dlg_addr_err"), tr("msg_target_prefix") + result, parent=self.root)
            self.connect_addr.focus()
            return

        # Check for duplicate
        try:
            existing = list_rules()
            for r in existing:
                editing_same = (edit_rtype and edit_lp and r.get("type") == edit_rtype and r["listenPort"] == edit_lp and (r["listenAddress"] == edit_la or edit_la == "0.0.0.0" or r["listenAddress"] == "0.0.0.0"))
                if not editing_same and r.get("type") == rtype and r["listenPort"] == lp and (r["listenAddress"] == la or la == "0.0.0.0" or r["listenAddress"] == "0.0.0.0"):
                    if not messagebox.askyesno(tr("dlg_dup_title"),
                            tr("dlg_dup_msg", lp, r["listenAddress"], r["connectAddress"]),
                            parent=self.root):
                        return
        except Exception:
            pass

        self._set_status(tr("status_adding"))
        try:
            do_netsh("add", la, lp, ca, cp, rtype=rtype)
            if firewall:
                fw_open(lp, "PortProxy_%s_%s" % (rtype, lp))
            self._set_status(tr("status_add_ok_fw") if firewall else tr("status_add_ok"), "ok")
            self.listen_port.delete(0, "end")
            self.connect_addr.delete(0, "end")
            self.connect_port.delete(0, "end")
            self.refresh_rules()
        except Exception as e:
            self._set_status(tr("status_add_fail", str(e)), "err")
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_add_fail", str(e)), parent=self.root)

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning(tr("dlg_hint"), tr("msg_select_rule"), parent=self.root)
            return
        values = self.tree.item(sel[0])["values"]
        addr, port = values[0].strip(), values[1]
        rtype = values[5] if len(values) > 5 else "v4tov4"
        if not messagebox.askyesno(tr("dlg_del_title"),
                tr("dlg_del_msg", addr, port), parent=self.root):
            return
        self._set_status(tr("status_deleting"))
        try:
            do_netsh("delete", addr, port, rtype=rtype)
            self._set_status(tr("status_delete_ok"), "ok")
            self.refresh_rules()
        except Exception as e:
            self._set_status(tr("status_delete_fail", str(e)), "err")
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_del_fail", str(e)), parent=self.root)

    def clear_all(self):
        if not messagebox.askyesno(tr("dlg_clear_title"),
                tr("dlg_clear_msg"), parent=self.root):
            return
        self._set_status(tr("status_clearing"))
        try:
            for _t in TYPES:
                try:
                    do_netsh("delete", "", "", rtype=_t)
                except Exception:
                    pass
            self._set_status(tr("status_clear_ok"), "ok")
            self.refresh_rules()
        except Exception as e:
            self._set_status(tr("status_clear_fail", str(e)), "err")
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_clear_fail", str(e)), parent=self.root)

    def _context_menu(self, event):
        sel = self.tree.identify_row(event.y)
        if sel:
            self.tree.selection_set(sel)
            self.tree_menu.post(event.x_root, event.y_root)

    def check_admin(self):
        admin = is_admin()
        if admin:
            self.admin_label.config(text=tr("admin_ok"), fg="#86efac")
            self.elevate_btn.pack_forget()
        else:
            self.admin_label.config(text=tr("admin_no"), fg="#fca5a5")
            self.elevate_btn.pack(side="right", padx=(0, 12))

    def elevate(self):
        if relaunch_as_admin():
            self.root.destroy()
            sys.exit(0)
        messagebox.showwarning(tr("dlg_elevate_title"), tr("dlg_elevate_fail"), parent=self.root)


    def edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning(tr("dlg_hint"), tr("msg_select_rule"), parent=self.root)
            return
        values = self.tree.item(sel[0])["values"]
        addr = values[0].strip()
        port = values[1]
        rtype = values[5] if len(values) > 5 else "v4tov4"
        self.listen_addr.delete(0, "end")
        self.listen_addr.insert(0, addr if addr != "0.0.0.0" else "")
        self.listen_port.delete(0, "end")
        self.listen_port.insert(0, port)
        self.connect_addr.delete(0, "end")
        self.connect_port.delete(0, "end")
        self.rule_type.set(rtype)
        self.edit_var.set(rtype)
        self.edit_addr.set(addr if addr != "0.0.0.0" else "")
        self.edit_lp.set(port)
        self._set_status(tr("status_edit_mode"), "info")
        self.listen_port.focus()

    def export_json(self):
        try:
            rules = list_rules()
        except Exception as e:
            messagebox.showerror(tr("dlg_err_title"), tr("err_read_rules", str(e)), parent=self.root)
            return
        if not rules:
            messagebox.showinfo(tr("dlg_export_title"), tr("dlg_export_empty"), parent=self.root)
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[(tr("export_filetype"), "*.json")], title=tr("export_title"))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False, indent=2)
            self._set_status(tr("status_export_ok", len(rules)), "ok")
        except Exception as e:
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_export_fail", str(e)), parent=self.root)

    def import_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            filetypes=[(tr("filetype_json"), "*.json"), (tr("filetype_csv"), "*.csv"), (tr("filetype_all"), "*.*")],
            title=tr("dlg_import_title"))
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        try:
            # Try UTF-8 first, fallback to GBK
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(path, "r", encoding="gbk") as f:
                    content = f.read()
        except Exception as e:
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_read_fail", str(e)), parent=self.root)
            return
        if ext == ".csv":
            rules, csv_errors = parse_csv(content)
            if csv_errors and not rules:
                messagebox.showerror(tr("dlg_err_title"), csv_errors[0], parent=self.root)
                return
        else:
            try:
                rules = json.loads(content)
            except Exception as e:
                messagebox.showerror(tr("dlg_err_title"), tr("dlg_json_fail", str(e)), parent=self.root)
                return
            csv_errors = []
            if not isinstance(rules, list):
                messagebox.showerror(tr("dlg_err_title"), tr("dlg_format_err"), parent=self.root)
                return
        try:
            added, skipped = import_rules(rules)
            msg = tr("status_import_ok", len(added))
            if skipped:
                msg += tr("import_skipped", len(skipped))
            if csv_errors:
                msg += "\n" + "\n".join(csv_errors[:5])
            self._set_status(msg, "ok" if added else "err")
            messagebox.showinfo(tr("dlg_import_done"), msg, parent=self.root)
            self.refresh_rules()
        except Exception as e:
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_import_fail", str(e)), parent=self.root)
    def show_about(self):
        messagebox.showinfo(tr("dlg_about_title"), tr("dlg_about_msg"), parent=self.root)

    # ── theme toggle ──
    def toggle_theme(self):
        self._dark = self._dark_var.get()
        _write_setting("Theme", "dark" if self._dark else "light")
        # Rebuild entire UI with new theme
        self.C = THEME_DARK if self._dark else THEME_LIGHT
        for widget in self.root.winfo_children():
            widget.destroy()
        self.root.configure(bg=self.C["bg"])
        self._setup_styles()
        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_log_panel()
        self._build_statusbar()
        self._bind_keys()
        self.refresh_rules()
        self.check_admin()
        self._init_tray()
        self._init_startup_toggle()
        if self._log_visible.get():
            self._log_frame.pack(side="bottom", fill="x", padx=20, pady=(0, 4))
            self._refresh_log()
        self._set_status(tr("status_theme_dark") if self._dark else tr("status_theme_light"), "ok")

    # ── WSL detection ──
    def detect_wsl_action(self):
        self._set_status(tr("status_wsl_detecting"))
        result = detect_wsl()
        if result["available"]:
            msg = tr("dlg_wsl_found", result["wsl_ip"], result["host_ip"])
            if messagebox.askyesno(tr("dlg_wsl_title"), msg, parent=self.root):
                self.connect_addr.delete(0, "end")
                self.connect_addr.insert(0, result["wsl_ip"])
                self.connect_addr.config(fg=self.C["text"])
                self._set_status(tr("status_wsl_filled", result["wsl_ip"]), "ok")
        else:
            messagebox.showinfo(tr("dlg_wsl_title"), tr("dlg_wsl_none"), parent=self.root)
            self._set_status(tr("status_wsl_none"), "info")

    # ── system tray (ctypes Shell_NotifyIcon, no dependencies) ──
    def _init_tray(self):
        self.tray_icon = None
        self._minimize_to_tray = True
        self.root.bind("<Unmap>", self._on_unmap)

    def _build_tray_icon(self):
        if self.tray_icon is not None:
            return
        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = self.root.winfo_id()
        nid.uID = 1
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP
        nid.uCallbackMessage = WM_TRAY_MSG
        try:
            nid.hIcon = ctypes.windll.user32.SendMessageW(self.root.winfo_id(), 0x007F, 2, 0)
        except Exception:
            nid.hIcon = 0
        if not nid.hIcon:
            nid.hIcon = ctypes.windll.user32.LoadIconW(0, 32512)
        nid.szTip = tr("app_title")
        ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        self.tray_icon = nid

    def _remove_tray_icon(self):
        if self.tray_icon is None:
            return
        ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self.tray_icon))
        self.tray_icon = None

    def _on_unmap(self, event=None):
        if getattr(self, "_minimize_to_tray", True):
            self._build_tray_icon()
            if self.tray_icon is not None:
                self.root.withdraw()

    def hide_to_tray(self):
        self._build_tray_icon()
        if self.tray_icon is not None:
            self.root.withdraw()

    def show_from_tray(self):
        self.root.deiconify()
        self.root.lift()
        self.root.update_idletasks()

    def toggle_tray(self):
        if self.root.winfo_viewable():
            self.hide_to_tray()
        else:
            self.show_from_tray()

    def _install_tray_wndproc(self):
        if getattr(self, "_wnd_subclassed", False):
            return
        self._wnd_subclassed = True
        hwnd = self.root.winfo_id()
        old = ctypes.windll.user32.GetWindowLongPtrW(hwnd, GWL_WNDPROC)
        self._old_wndproc = old
        def wnd_proc(hwnd_, msg, wparam, lparam):
            if msg == WM_TRAY_MSG:
                if lparam == WM_LBUTTONUP or lparam == WM_RBUTTONUP:
                    self.root.after(0, self._tray_menu)
                return 0
            result = ctypes.windll.user32.CallWindowProcW(self._old_wndproc, hwnd_, msg, wparam, lparam)
            return int(result) if result is not None else 0
        # Return type must be pointer-sized (LONG_PTR), not 32-bit c_long.
        self._wndproc_cb = ctypes.WINFUNCTYPE(LONG_PTR, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)(wnd_proc)
        ctypes.windll.user32.SetWindowLongPtrW(hwnd, GWL_WNDPROC, self._wndproc_cb)

    def _tray_menu(self):
        if not hasattr(self, "_tray_menu_w"):
            m = tk.Menu(self.root, tearoff=0, font=FONT_UI)
            m.add_command(label=tr("tray_show"), command=self.show_from_tray)
            m.add_command(label=tr("tray_refresh"), command=self.refresh_rules)
            m.add_separator()
            m.add_command(label=tr("tray_exit"), command=self.quit_app)
            self._tray_menu_w = m
        try:
            self._tray_menu_w.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        except Exception:
            pass

    def close_to_tray(self):
        if self.root.winfo_viewable():
            self.hide_to_tray()
        else:
            self.quit_app()

    def quit_app(self):
        try:
            self._remove_tray_icon()
        except Exception:
            pass
        self.root.destroy()
        sys.exit(0)

    # ── startup persistence ──
    def _init_startup_toggle(self):
        try:
            self.startup_var.set(startup_enabled())
        except Exception:
            pass

    def toggle_startup(self):
        try:
            enable = self.startup_var.get()
            if set_startup(enable):
                self._set_status(tr("status_startup_on") if enable else tr("status_startup_off"), "ok")
            else:
                self.startup_var.set(not enable)
                messagebox.showerror(tr("dlg_err_title"), tr("dlg_startup_fail"), parent=self.root)
        except Exception as e:
            self.startup_var.set(not self.startup_var.get())
            messagebox.showerror(tr("dlg_err_title"), tr("dlg_op_fail", str(e)), parent=self.root)


# ── Main ─────────────────────────────────────────────

def main():
    if os.environ.get("PP_NO_ELEVATE") != "1" and not is_admin():
        try:
            if relaunch_as_admin():
                sys.exit(0)
        except Exception:
            pass
    root = tk.Tk()
    app = PortProxyApp(root)
    app._install_tray_wndproc()
    root.mainloop()


if __name__ == "__main__":
    main()

