#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy desktop manager (tkinter)"""

import os, re, subprocess, tempfile, tkinter as tk, ctypes, sys, json
from tkinter import ttk, messagebox

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
    try:
        r = subprocess.run(
            ["netsh", "interface", "portproxy"] + args,
            capture_output=True,
        )
        out = _decode(r.stdout)
        err = _decode(r.stderr)
        if r.returncode != 0 and not out and not err:
            return _netsh_shell(args)
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
    try:
        r = subprocess.run(["netsh", "advfirewall"] + args, capture_output=True)
        return r.returncode, _decode(r.stdout), _decode(r.stderr)
    except Exception as e:
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

def relaunch_as_admin():
    """Request UAC elevation and relaunch this script. Returns True if launched."""
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, ""
        else:
            try:
                self.startup_var.set(startup_enabled())
            except Exception:
                pass
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
        return False, "端口不能为空"
    try:
        p = int(s)
    except ValueError:
        return False, "端口必须为数字"
    if p < 1 or p > 65535:
        return False, "端口范围: 1-65535"
    return True, p


def validate_ip(ip_str):
    """Validate IPv4 address. Returns (True, ip) or (False, error_msg)."""
    s = ip_str.strip()
    if s == "*":
        return True, "*"
    if not s:
        return False, "地址不能为空"
    parts = s.split(".")
    if len(parts) != 4:
        return False, "IP 格式错误 (应为 x.x.x.x)"
    for part in parts:
        try:
            n = int(part)
        except ValueError:
            return False, "IP 各部分必须为数字"
        if n < 0 or n > 255:
            return False, "IP 各部分范围: 0-255"
    return True, s


def _friendly_error(raw):
    """Translate netsh error messages to Chinese."""
    if not raw:
        return "操作失败，请检查是否以管理员权限运行"
    if "elevation" in raw.lower() or "提升" in raw:
        return "需要管理员权限，请以管理员身份运行此程序"
    if "already exists" in raw.lower() or "已存在" in raw:
        return "该规则已存在"
    if "not found" in raw.lower() or "找不到" in raw:
        return "未找到指定规则"
    if "parameter" in raw.lower():
        return "参数错误: " + raw.strip()
    return raw.strip() or "操作失败"


# ── color & style constants ──────────────────────────

CLR_BG         = "#f0f2f5"
CLR_CARD       = "#ffffff"
CLR_PRIMARY    = "#2563eb"
CLR_PRIMARY_H  = "#1d4ed8"
CLR_DANGER     = "#ef4444"
CLR_DANGER_H   = "#dc2626"
CLR_SUCCESS    = "#16a34a"
CLR_TEXT       = "#1e293b"
CLR_TEXT_SEC   = "#64748b"
CLR_BORDER     = "#e2e8f0"
CLR_HEADER_BG  = "#1e3a5f"
CLR_HEADER_FG  = "#ffffff"
CLR_ROW_ALT    = "#f8fafc"
FONT_UI      = ("Microsoft YaHei UI", 9)
FONT_MONO    = ("Cascadia Code", 10)
FONT_H1      = ("Microsoft YaHei UI", 18, "bold")
FONT_H2      = ("Microsoft YaHei UI", 11, "bold")
FONT_SMALL   = ("Microsoft YaHei UI", 8)


# ── GUI Application ──────────────────────────────────

class PortProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PortProxy - 端口转发管理器")
        self.root.geometry("960x620")
        self.root.minsize(720, 440)
        self.root.configure(bg=CLR_BG)
        self._setup_styles()
        self._build_menu()
        self._build_header()
        self._build_body()
        self._build_statusbar()
        self._bind_keys()
        self.refresh_rules()
        self.check_admin()
        self._init_tray()
        self._init_startup_toggle()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=FONT_UI, background=CLR_BG)
        style.configure("TFrame", background=CLR_BG)
        style.configure("Card.TFrame", background=CLR_CARD, relief="solid", borderwidth=1)
        style.configure("TLabel", background=CLR_CARD, foreground=CLR_TEXT, font=FONT_UI)
        style.configure("Bg.TLabel", background=CLR_BG, foreground=CLR_TEXT)
        style.configure("Header.TLabel", background=CLR_HEADER_BG, foreground=CLR_HEADER_FG, font=FONT_H1)
        style.configure("SubHeader.TLabel", background=CLR_HEADER_BG, foreground="#94a3b8", font=FONT_UI)
        style.configure("Section.TLabel", background=CLR_CARD, foreground=CLR_TEXT, font=FONT_H2)
        style.configure("Hint.TLabel", background=CLR_CARD, foreground=CLR_TEXT_SEC, font=FONT_SMALL)
        style.configure("Status.TLabel", background=CLR_BG, foreground=CLR_TEXT_SEC, font=FONT_UI)
        style.configure("StatusOk.TLabel", background=CLR_BG, foreground=CLR_SUCCESS, font=FONT_UI)
        style.configure("StatusErr.TLabel", background=CLR_BG, foreground=CLR_DANGER, font=FONT_UI)
        style.configure("Count.TLabel", background=CLR_CARD, foreground=CLR_PRIMARY, font=FONT_H2)
        style.configure("Primary.TButton", background=CLR_PRIMARY, foreground="#ffffff",
            borderwidth=0, focusthickness=0, padding=(16, 6))
        style.map("Primary.TButton", background=[("active", CLR_PRIMARY_H), ("pressed", CLR_PRIMARY_H)],
            foreground=[("active", "#ffffff")])
        style.configure("Danger.TButton", background="#ffffff", foreground=CLR_DANGER,
            borderwidth=1, bordercolor=CLR_BORDER, focusthickness=0, padding=(12, 5))
        style.map("Danger.TButton", background=[("active", "#fef2f2"), ("pressed", "#fee2e2")],
            foreground=[("active", CLR_DANGER_H)])
        style.configure("Secondary.TButton", background="#ffffff", foreground=CLR_TEXT_SEC,
            borderwidth=1, bordercolor=CLR_BORDER, focusthickness=0, padding=(12, 5))
        style.map("Secondary.TButton", background=[("active", CLR_BG), ("pressed", CLR_BORDER)],
            foreground=[("active", CLR_TEXT)])
        style.configure("TEntry", fieldbackground=CLR_CARD, foreground=CLR_TEXT,
            borderwidth=1, bordercolor=CLR_BORDER, padding=6)
        style.map("TEntry", bordercolor=[("focus", CLR_PRIMARY)],
            lightcolor=[("focus", CLR_PRIMARY)], darkcolor=[("focus", CLR_PRIMARY)])
        style.configure("Treeview", background=CLR_CARD, foreground=CLR_TEXT,
            fieldbackground=CLR_CARD, rowheight=32, font=FONT_MONO, borderwidth=0)
        style.configure("Treeview.Heading", background="#f1f5f9", foreground=CLR_TEXT_SEC,
            font=("Microsoft YaHei UI", 9, "bold"), borderwidth=0, padding=(10, 6))
        style.map("Treeview.Heading", background=[("active", "#e2e8f0")])
        style.map("Treeview", background=[("selected", CLR_PRIMARY)],
            foreground=[("selected", "#ffffff")])
        style.configure("TScrollbar", background=CLR_BG, troughcolor=CLR_BG, borderwidth=0, arrowsize=14)

    def _build_menu(self):
        menubar = tk.Menu(self.root, font=FONT_UI)
        file_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        file_menu.add_command(label="刷新 (F5)", command=self.refresh_rules)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit)
        menubar.add_cascade(label="文件", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        help_menu.add_command(label="关于", command=self.show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)
        settings_menu = tk.Menu(menubar, tearoff=0, font=FONT_UI)
        self.startup_var = tk.BooleanVar(value=False)
        settings_menu.add_checkbutton(label="开机自启", variable=self.startup_var,
            command=self.toggle_startup, font=FONT_UI)
        settings_menu.add_command(label="隐入托盘", command=self.hide_to_tray)
        settings_menu.add_separator()
        settings_menu.add_command(label="关于本程序", command=self.show_about)
        menubar.add_cascade(label="设置", menu=settings_menu)
        self.root.config(menu=menubar)

    def _build_header(self):
        header = tk.Frame(self.root, bg=CLR_HEADER_BG, height=72)
        header.pack(fill="x")
        header.pack_propagate(False)
        inner = tk.Frame(header, bg=CLR_HEADER_BG)
        inner.pack(fill="both", expand=True, padx=24)
        logo = tk.Frame(inner, bg=CLR_PRIMARY, width=38, height=38)
        logo.pack(side="left", padx=(0, 14))
        logo.pack_propagate(False)
        tk.Label(logo, text="PP", bg=CLR_PRIMARY, fg="#ffffff",
                 font=("Segoe UI", 12, "bold")).pack(expand=True)
        title_frame = tk.Frame(inner, bg=CLR_HEADER_BG)
        title_frame.pack(side="left")
        tk.Label(title_frame, text="端口转发管理器", bg=CLR_HEADER_BG,
                 fg=CLR_HEADER_FG, font=FONT_H1).pack(anchor="w")
        tk.Label(title_frame, text="基于 Windows netsh interface portproxy",
                 bg=CLR_HEADER_BG, fg="#94a3b8", font=FONT_UI).pack(anchor="w")
        refresh_btn = tk.Button(inner, text=" 刷新", command=self.refresh_rules,
            bg=CLR_HEADER_BG, fg="#94a3b8", font=FONT_UI,
            bd=0, activebackground="#2a4a6f", activeforeground="#ffffff",
            cursor="hand2", padx=14, pady=4)
        refresh_btn.pack(side="right")

        self.admin_label = tk.Label(inner, text="", bg=CLR_HEADER_BG, fg="#94a3b8", font=FONT_UI)
        self.admin_label.pack(side="right", padx=(0, 12))
        self.elevate_btn = tk.Button(inner, text="以管理员身份重启", command=self.elevate,
            bg=CLR_PRIMARY, fg="#ffffff", font=("Microsoft YaHei UI", 9, "bold"),
            bd=0, activebackground=CLR_PRIMARY_H, activeforeground="#ffffff",
            cursor="hand2", padx=12, pady=5)
        self.elevate_btn.pack(side="right", padx=(0, 12))
        self.elevate_btn.pack_forget()

    def _build_body(self):
        body = tk.Frame(self.root, bg=CLR_BG)
        body.pack(fill="both", expand=True, padx=20, pady=(16, 0))

        # ── Add Rule card ──
        add_card = tk.Frame(body, bg=CLR_CARD, bd=1, relief="solid",
                            highlightbackground=CLR_BORDER, highlightthickness=0)
        add_card.pack(fill="x", pady=(0, 12))
        card_header = tk.Frame(add_card, bg=CLR_CARD)
        card_header.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(card_header, text="添加转发规则", bg=CLR_CARD,
                 fg=CLR_TEXT, font=FONT_H2).pack(side="left")
        form = tk.Frame(add_card, bg=CLR_CARD)
        form.pack(fill="x", padx=20, pady=(0, 16))
        self._field(form, "监听地址", 0, 0)
        self.listen_addr = self._entry(form, 0, 1, 18, "0.0.0.0")
        self.listen_addr.insert(0, "0.0.0.0")
        tk.Label(form, text=":", bg=CLR_CARD, fg=CLR_TEXT_SEC,
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=2, padx=(6, 6))
        self.listen_port = self._entry(form, 0, 3, 8, "8080")
        tk.Label(form, text="→", bg=CLR_CARD, fg=CLR_TEXT_SEC,
                 font=("Segoe UI", 14)).grid(row=0, column=4, padx=(10, 10))
        self._field(form, "目标地址", 0, 5)
        self.connect_addr = self._entry(form, 0, 6, 18, "192.168.1.100")
        tk.Label(form, text=":", bg=CLR_CARD, fg=CLR_TEXT_SEC,
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=7, padx=(6, 6))
        self.connect_port = self._entry(form, 0, 8, 8, "80")
        tk.Label(form, text="类型", bg=CLR_CARD, fg=CLR_TEXT_SEC, font=FONT_SMALL).grid(row=0, column=9, padx=(16, 4))
        self.rule_type = tk.StringVar(value="v4tov4")
        type_combo = ttk.Combobox(form, textvariable=self.rule_type, state="readonly",
            values=list(TYPES), width=9, font=FONT_UI)
        type_combo.grid(row=0, column=10, padx=(0, 8))
        self.fw_var = tk.BooleanVar(value=False)
        fw_chk = tk.Checkbutton(form, text="放行防火墙", variable=self.fw_var,
            bg=CLR_CARD, fg=CLR_TEXT_SEC, font=FONT_SMALL, cursor="hand2")
        fw_chk.grid(row=0, column=11, padx=(4, 8))
        self.edit_var = tk.StringVar(value="")
        self.edit_lp = tk.StringVar(value="")
        self.edit_addr = tk.StringVar(value="")
        add_btn = tk.Button(form, text="+ 添加规则", command=self.add_rule,
            bg=CLR_PRIMARY, fg="#ffffff", font=("Microsoft YaHei UI", 10, "bold"),
            bd=0, activebackground=CLR_PRIMARY_H, activeforeground="#ffffff",
            cursor="hand2", padx=20, pady=7)
        add_btn.grid(row=0, column=11, padx=(8, 0))
        tk.Label(add_card, text="提示：支持 v4tov4/v4tov6/v6tov4/v6tov6 四种类型；添加/删除需管理员权限",
                 bg=CLR_CARD, fg=CLR_TEXT_SEC, font=FONT_SMALL).pack(
                     anchor="w", padx=20, pady=(0, 12))

        # ── Rules table card ──
        table_card = tk.Frame(body, bg=CLR_CARD, bd=1, relief="solid",
                              highlightbackground=CLR_BORDER, highlightthickness=0)
        table_card.pack(fill="both", expand=True)
        table_header = tk.Frame(table_card, bg=CLR_CARD)
        table_header.pack(fill="x", padx=20, pady=(16, 8))
        tk.Label(table_header, text="当前规则", bg=CLR_CARD,
                 fg=CLR_TEXT, font=FONT_H2).pack(side="left")
        self.rule_count_label = tk.Label(table_header, text="",
            bg=CLR_CARD, fg=CLR_PRIMARY, font=FONT_H2)
        self.rule_count_label.pack(side="left", padx=(8, 0))
        clear_btn = tk.Button(table_header, text="清空全部", command=self.clear_all,
            bg=CLR_CARD, fg=CLR_DANGER, font=FONT_UI,
            bd=1, relief="solid", activebackground="#fef2f2",
            activeforeground=CLR_DANGER_H, cursor="hand2", padx=12, pady=3)
        clear_btn.pack(side="right")
        imp_btn = tk.Button(table_header, text="导入", command=self.import_json,
            bg=CLR_CARD, fg=CLR_PRIMARY, font=FONT_UI,
            bd=1, relief="solid", activebackground="#eff6ff",
            activeforeground=CLR_PRIMARY_H, cursor="hand2", padx=12, pady=3)
        imp_btn.pack(side="right", padx=(0, 8))
        exp_btn = tk.Button(table_header, text="导出", command=self.export_json,
            bg=CLR_CARD, fg=CLR_PRIMARY, font=FONT_UI,
            bd=1, relief="solid", activebackground="#eff6ff",
            activeforeground=CLR_PRIMARY_H, cursor="hand2", padx=12, pady=3)
        exp_btn.pack(side="right", padx=(0, 8))
        tree_frame = tk.Frame(table_card, bg=CLR_CARD)
        tree_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        cols = ("listenAddr", "listenPort", "connectAddr", "connectPort", "protocol", "type", "actions")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse", height=10)
        self.tree.heading("listenAddr", text="  监听地址")
        self.tree.heading("listenPort", text="监听端口")
        self.tree.heading("connectAddr", text="  目标地址")
        self.tree.heading("connectPort", text="目标端口")
        self.tree.heading("protocol", text="协议")
        self.tree.heading("type", text="类型")
        self.tree.heading("actions", text="操作")
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
        self.tree_menu = tk.Menu(self.root, tearoff=0, bg="#ffffff", fg=CLR_TEXT,
            font=FONT_UI, activebackground=CLR_PRIMARY, activeforeground="#ffffff",
            bd=1, relief="solid")
        self.tree_menu.add_command(label="编辑选中规则", command=self.edit_selected)
        self.tree_menu.add_command(label="删除选中规则", command=self.delete_selected)
        self.tree.bind("<Button-3>", self._context_menu)
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        self.tree.tag_configure("odd", background=CLR_CARD)
        self.tree.tag_configure("even", background=CLR_ROW_ALT)

    def _field(self, parent, text, row, col):
        lbl = tk.Label(parent, text=text, bg=CLR_CARD, fg=CLR_TEXT_SEC, font=FONT_SMALL)
        lbl.grid(row=row, column=col, sticky="sw", padx=(0, 4), pady=(0, 2))

    def _entry(self, parent, row, col, width, placeholder=""):
        e = tk.Entry(parent, width=width, font=FONT_MONO, bg=CLR_CARD,
                     fg=CLR_TEXT_SEC if placeholder else CLR_TEXT,
                     bd=1, relief="solid",
                     insertbackground=CLR_TEXT, selectbackground=CLR_PRIMARY,
                     selectforeground="#ffffff")
        e.grid(row=row, column=col, sticky="w")
        e.configure(highlightbackground=CLR_BORDER, highlightcolor=CLR_PRIMARY,
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
            w.config(fg=CLR_TEXT)

    def _restore_placeholder(self, event, placeholder):
        w = event.widget
        if w.get() == "":
            w.insert(0, placeholder)
            w.config(fg=CLR_TEXT_SEC)

    def _build_statusbar(self):
        self.status = tk.Label(self.root, text="就绪", bg=CLR_BG,
            fg=CLR_TEXT_SEC, font=FONT_UI, anchor="w", padx=20, pady=8)
        self.status.pack(side="bottom", fill="x")

    def _bind_keys(self):
        self.root.protocol("WM_DELETE_WINDOW", self.close_to_tray)
        self.root.bind("<F5>", lambda e: self.refresh_rules())
        self.root.bind("<Control-r>", lambda e: self.refresh_rules())
        self.root.bind("<Return>", lambda e: self.add_rule())

    def _set_status(self, text, kind="info"):
        colors = {"info": CLR_TEXT_SEC, "ok": CLR_SUCCESS, "err": CLR_DANGER}
        self.status.config(text=text, fg=colors.get(kind, CLR_TEXT_SEC))
        self.root.update_idletasks()

    # ── actions ──────────────────────────────────────

    def refresh_rules(self):
        self._set_status("正在刷新...")
        try:
            rules = list_rules()
            self.tree.delete(*self.tree.get_children())
            for i, r in enumerate(rules):
                tag = "even" if i % 2 == 0 else "odd"
                self.tree.insert("", "end", values=(
                    "  " + r["listenAddress"], r["listenPort"],
                    "  " + r["connectAddress"], r["connectPort"],
                    "TCP", r.get("type", "v4tov4"),
                    "右键编辑 / 删除"
                ), tags=(tag,))
            count = len(rules)
            self.rule_count_label.config(text="({})".format(count) if count else "")
            self._set_status("共 {} 条规则".format(count), "ok")
        except Exception as e:
            self._set_status("刷新失败: {}".format(str(e)), "err")

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
            messagebox.showwarning("端口错误", result, parent=self.root)
            self.listen_port.focus()
            return

        # Validate connect port (if provided)
        if cp:
            ok, result = validate_port(cp)
            if not ok:
                messagebox.showwarning("端口错误", "目标" + result, parent=self.root)
                self.connect_port.focus()
                return

        # Validate IP addresses
        if la:
            ok, result = validate_ip(la)
            if not ok:
                messagebox.showwarning("地址错误", "监听" + result, parent=self.root)
                self.listen_addr.focus()
                return
        if not ca:
            messagebox.showwarning("提示", "请输入目标地址", parent=self.root)
            self.connect_addr.focus()
            return
        ok, result = validate_ip(ca)
        if not ok:
            messagebox.showwarning("地址错误", "目标" + result, parent=self.root)
            self.connect_addr.focus()
            return

        # Check for duplicate
        try:
            existing = list_rules()
            for r in existing:
                editing_same = (edit_rtype and edit_lp and r.get("type") == edit_rtype and r["listenPort"] == edit_lp and (r["listenAddress"] == edit_la or edit_la == "0.0.0.0" or r["listenAddress"] == "0.0.0.0"))
                if not editing_same and r.get("type") == rtype and r["listenPort"] == lp and (r["listenAddress"] == la or la == "0.0.0.0" or r["listenAddress"] == "0.0.0.0"):
                    if not messagebox.askyesno("规则可能重复",
                            "已存在监听端口 {} 的规则 ({} -> {})\n确定要继续添加吗？".format(
                                lp, r["listenAddress"], r["connectAddress"]),
                            parent=self.root):
                        return
        except Exception:
            pass

        self._set_status("正在添加规则...")
        try:
            do_netsh("add", la, lp, ca, cp, rtype=rtype)
            if firewall:
                fw_open(lp, "PortProxy_%s_%s" % (rtype, lp))
            self._set_status("规则添加成功" + ("（已放行防火墙）" if firewall else ""), "ok")
            self.listen_port.delete(0, "end")
            self.connect_addr.delete(0, "end")
            self.connect_port.delete(0, "end")
            self.refresh_rules()
        except Exception as e:
            self._set_status("添加失败: {}".format(str(e)), "err")
            messagebox.showerror("错误", "添加规则失败:\n{}".format(str(e)), parent=self.root)

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则", parent=self.root)
            return
        values = self.tree.item(sel[0])["values"]
        addr, port = values[0].strip(), values[1]
        rtype = values[5] if len(values) > 5 else "v4tov4"
        if not messagebox.askyesno("确认删除",
                "确定要删除规则 {}:{} 吗？".format(addr, port), parent=self.root):
            return
        self._set_status("正在删除规则...")
        try:
            do_netsh("delete", addr, port, rtype=rtype)
            self._set_status("规则删除成功", "ok")
            self.refresh_rules()
        except Exception as e:
            self._set_status("删除失败: {}".format(str(e)), "err")
            messagebox.showerror("错误", "删除规则失败:\n{}".format(str(e)), parent=self.root)

    def clear_all(self):
        if not messagebox.askyesno("确认清空",
                "确定要清空所有端口转发规则吗？\n此操作不可撤销。", parent=self.root):
            return
        self._set_status("正在清空所有规则...")
        try:
            for _t in TYPES:
                try:
                    do_netsh("delete", "", "", rtype=_t)
                except Exception:
                    pass
            self._set_status("已清空所有规则", "ok")
            self.refresh_rules()
        except Exception as e:
            self._set_status("清空失败: {}".format(str(e)), "err")
            messagebox.showerror("错误", "清空规则失败:\n{}".format(str(e)), parent=self.root)

    def _context_menu(self, event):
        sel = self.tree.identify_row(event.y)
        if sel:
            self.tree.selection_set(sel)
            self.tree_menu.post(event.x_root, event.y_root)

    def check_admin(self):
        admin = is_admin()
        if admin:
            self.admin_label.config(text="● 管理员权限", fg="#86efac")
            self.elevate_btn.pack_forget()
        else:
            self.admin_label.config(text="● 非管理员", fg="#fca5a5")
            self.elevate_btn.pack(side="right", padx=(0, 12))

    def elevate(self):
        if relaunch_as_admin():
            self.root.destroy()
            sys.exit(0)
        messagebox.showwarning("提权失败", "无法请求管理员权限。\n请右键本程序选择“以管理员身份运行”。", parent=self.root)


    def edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则", parent=self.root)
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
        self._set_status("编辑模式：修改后点击添加将更新该监听点", "info")
        self.listen_port.focus()

    def export_json(self):
        try:
            rules = list_rules()
        except Exception as e:
            messagebox.showerror("错误", "读取规则失败:\n{}".format(str(e)), parent=self.root)
            return
        if not rules:
            messagebox.showinfo("导出", "当前没有可导出的规则", parent=self.root)
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON 文件", "*.json")], title="导出规则")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False, indent=2)
            self._set_status("已导出 {} 条规则".format(len(rules)), "ok")
        except Exception as e:
            messagebox.showerror("错误", "导出失败:\n{}".format(str(e)), parent=self.root)

    def import_json(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(filetypes=[("JSON 文件", "*.json")], title="导入规则")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                rules = json.load(f)
        except Exception as e:
            messagebox.showerror("错误", "读取文件失败:\n{}".format(str(e)), parent=self.root)
            return
        if not isinstance(rules, list):
            messagebox.showerror("错误", "文件格式不正确：应为规则数组", parent=self.root)
            return
        try:
            added, skipped = import_rules(rules)
            msg = "已导入 {} 条规则".format(len(added))
            if skipped:
                msg += "，跳过 {} 条（重复或无效）".format(len(skipped))
            self._set_status(msg, "ok" if added else "err")
            messagebox.showinfo("导入完成", msg, parent=self.root)
            self.refresh_rules()
        except Exception as e:
            messagebox.showerror("错误", "导入失败:\n{}".format(str(e)), parent=self.root)
    def show_about(self):
        messagebox.showinfo("关于 PortProxy",
            "端口转发管理器 v1.0\n\n"
            "基于 Windows netsh interface portproxy\n"
            "管理员权限运行可添加/删除规则\n"
            "支持系统托盘与开机自启",
            parent=self.root)

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
        nid.szTip = "PortProxy 端口转发管理器"
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
            m.add_command(label="显示", command=self.show_from_tray)
            m.add_command(label="刷新", command=self.refresh_rules)
            m.add_separator()
            m.add_command(label="退出", command=self.quit_app)
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
                self._set_status("已" + ("开启" if enable else "关闭") + "开机自启", "ok")
            else:
                self.startup_var.set(not enable)
                messagebox.showerror("错误", "无法写入注册表，请检查权限或以管理员身份运行。", parent=self.root)
        except Exception as e:
            self.startup_var.set(not self.startup_var.get())
            messagebox.showerror("错误", "操作失败:\n{}".format(str(e)), parent=self.root)


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

