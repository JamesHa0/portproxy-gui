#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy desktop manager (tkinter)"""

import os, re, subprocess, tempfile, tkinter as tk
from tkinter import ttk, messagebox

# ── netsh logic ──────────────────────────────────────

def netsh(args):
    """Run netsh command. capture_output primary, shell redirect fallback."""
    try:
        r = subprocess.run(
            ["netsh", "interface", "portproxy"] + args,
            capture_output=True, text=True,
        )
        out = r.stdout or ""
        err = r.stderr or ""
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
                with open(tmp, "r", encoding="utf-8", errors="replace") as f:
                    output = f.read()
                os.remove(tmp)
            except Exception:
                pass
        return r.returncode, output, ""
    except Exception as e:
        return 1, "", str(e)


def list_rules():
    code, out, err = netsh(["show", "v4tov4"])
    if code != 0:
        raise RuntimeError((err or out).strip() or "netsh error")
    pat = re.compile(r"(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+)")
    rules = []
    for line in out.splitlines():
        m = pat.search(line)
        if m:
            rules.append({
                "listenAddress": m.group(1), "listenPort": m.group(2),
                "connectAddress": m.group(3), "connectPort": m.group(4),
            })
    return rules


def do_netsh(op, listen_addr, listen_port, connect_addr="", connect_port=""):
    args = [op, "v4tov4", "listenport=" + str(listen_port or "")]
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
        add_btn = tk.Button(form, text="+ 添加规则", command=self.add_rule,
            bg=CLR_PRIMARY, fg="#ffffff", font=("Microsoft YaHei UI", 10, "bold"),
            bd=0, activebackground=CLR_PRIMARY_H, activeforeground="#ffffff",
            cursor="hand2", padx=20, pady=7)
        add_btn.grid(row=0, column=9, padx=(20, 0))
        tk.Label(add_card, text="提示：添加/删除规则需要管理员权限运行",
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
        tree_frame = tk.Frame(table_card, bg=CLR_CARD)
        tree_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        cols = ("listenAddr", "listenPort", "connectAddr", "connectPort", "protocol")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                  selectmode="browse", height=10)
        self.tree.heading("listenAddr", text="  监听地址")
        self.tree.heading("listenPort", text="监听端口")
        self.tree.heading("connectAddr", text="  目标地址")
        self.tree.heading("connectPort", text="目标端口")
        self.tree.heading("protocol", text="协议")
        self.tree.column("listenAddr", width=180, anchor="w")
        self.tree.column("listenPort", width=100, anchor="center")
        self.tree.column("connectAddr", width=180, anchor="w")
        self.tree.column("connectPort", width=100, anchor="center")
        self.tree.column("protocol", width=70, anchor="center")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree_menu = tk.Menu(self.root, tearoff=0, bg="#ffffff", fg=CLR_TEXT,
            font=FONT_UI, activebackground=CLR_PRIMARY, activeforeground="#ffffff",
            bd=1, relief="solid")
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
                    "TCP"
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
                if r["listenPort"] == lp and (r["listenAddress"] == la or la == "0.0.0.0" or r["listenAddress"] == "0.0.0.0"):
                    if not messagebox.askyesno("规则可能重复",
                            "已存在监听端口 {} 的规则 ({} -> {})\n确定要继续添加吗？".format(
                                lp, r["listenAddress"], r["connectAddress"]),
                            parent=self.root):
                        return
        except Exception:
            pass

        self._set_status("正在添加规则...")
        try:
            do_netsh("add", la, lp, ca, cp)
            self._set_status("规则添加成功", "ok")
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
        if not messagebox.askyesno("确认删除",
                "确定要删除规则 {}:{} 吗？".format(addr, port), parent=self.root):
            return
        self._set_status("正在删除规则...")
        try:
            do_netsh("delete", addr, port)
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
            do_netsh("delete", "", "")
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

    def show_about(self):
        messagebox.showinfo("关于 PortProxy",
            "端口转发管理器 v1.0\n\n"
            "基于 Windows netsh interface portproxy\n"
            "管理员权限运行可添加/删除规则",
            parent=self.root)


# ── Main ─────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = PortProxyApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
