#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy graphical manager (web backend)"""

import json, os, re, subprocess, threading, webbrowser, tempfile, ctypes
from http.server import HTTPServer, BaseHTTPRequestHandler

HOST = "127.0.0.1"
PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---- admin detection -------------------------------------------------

def is_admin():
    """True/False if admin status can be determined, else None."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


# ---- netsh helpers ----------------------------------------------------

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
    """Run netsh command. Capture bytes, decode with GBK fallback."""
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
    """Fallback: redirect to temp file, then decode with GBK fallback."""
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
    code, out, err = netsh(["show", "v4tov4"])
    if code != 0:
        raise RuntimeError(_friendly_error((err or out).strip()))
    pat = re.compile(r'(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+|\*)\s+(\d+)')
    rules = []
    for line in out.splitlines():
        m = pat.search(line)
        if m:
            rules.append({
                "listenAddress": m.group(1), "listenPort": m.group(2),
                "connectAddress": m.group(3), "connectPort": m.group(4),
                "protocol": "tcp",
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
        raw = (err or out).strip()
        raise NetshError(_friendly_error(raw),
                         need_admin=("提升" in raw or "elevation" in raw.lower()))


# ---- validation -------------------------------------------------------

def validate_port(port_str):
    s = (port_str or "").strip()
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
    s = (ip_str or "").strip()
    if s in ("", "*"):
        return True, s
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
    if not raw:
        return "操作失败，请检查是否以管理员权限运行"
    low = raw.lower()
    if "elevation" in low or "提升" in raw:
        return "需要管理员权限，请以管理员身份运行此程序"
    if "already exists" in low or "已存在" in raw:
        return "该规则已存在"
    if "not found" in low or "找不到" in raw:
        return "未找到指定规则"
    if "parameter" in low:
        return "参数错误: " + raw.strip()
    return raw.strip() or "操作失败"


class NetshError(Exception):
    def __init__(self, message, need_admin=False):
        super().__init__(message)
        self.message = message
        self.need_admin = need_admin


# ---- HTTP handler -----------------------------------------------------

class Handler(BaseHTTPRequestHandler):

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, path, status=200):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            return self._json({"error": "not found"}, 404)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n > 0:
                return json.loads(self.rfile.read(n))
        except Exception:
            pass
        return {}

    def do_GET(self):
        try:
            if self.path in ("/", "/index.html"):
                self._html(os.path.join(BASE_DIR, "index.html"))
            elif self.path == "/api/rules":
                rules = list_rules()
                self._json({"ok": True, "rules": rules, "admin": is_admin()})
            elif self.path == "/api/status":
                self._json({"ok": True, "admin": is_admin()})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def do_POST(self):
        try:
            data = self._body()
            if self.path == "/api/rules":
                if data.get("action") == "clear":
                    try:
                        rules = list_rules()
                    except Exception as e:
                        return self._json({"ok": False, "error": str(e)}, 400)
                    count = 0
                    for r in rules:
                        try:
                            do_netsh("delete", r["listenAddress"], r["listenPort"])
                            count += 1
                        except Exception:
                            pass
                    return self._json({"ok": True, "message": "cleared", "count": count})
                # add rule
                la = str(data.get("listenAddress") or "").strip()
                lp = str(data.get("listenPort") or "").strip()
                ca = str(data.get("connectAddress") or "").strip()
                cp = str(data.get("connectPort") or "").strip()
                ok, res = validate_port(lp)
                if not ok:
                    return self._json({"ok": False, "error": res}, 400)
                ok, res = validate_ip(ca)
                if not ok:
                    return self._json({"ok": False, "error": "目标" + res}, 400)
                if cp:
                    ok, res = validate_port(cp)
                    if not ok:
                        return self._json({"ok": False, "error": "目标" + res}, 400)
                if la:
                    ok, res = validate_ip(la)
                    if not ok:
                        return self._json({"ok": False, "error": "监听" + res}, 400)
                # duplicate check
                la_norm = la if la else "0.0.0.0"
                try:
                    existing = list_rules()
                    for r in existing:
                        ra = "0.0.0.0" if r["listenAddress"] in ("", "*") else r["listenAddress"]
                        if ra == la_norm and r["listenPort"] == lp:
                            return self._json(
                                {"ok": False, "error": "该规则已存在 ({}:{})".format(la_norm, lp),
                                 "duplicate": True}, 409)
                except Exception:
                    pass
                try:
                    do_netsh("add", la, lp, ca, cp)
                except NetshError as e:
                    return self._json({"ok": False, "error": e.message,
                                       "needAdmin": e.need_admin}, 400)
                self._json({"ok": True, "message": "rule added"})
            elif self.path == "/api/rules/delete":
                la = str(data.get("listenAddress") or "").strip()
                lp = str(data.get("listenPort") or "").strip()
                ok, res = validate_port(lp)
                if not ok:
                    return self._json({"ok": False, "error": res}, 400)
                try:
                    do_netsh("delete", la, lp)
                except NetshError as e:
                    return self._json({"ok": False, "error": e.message,
                                       "needAdmin": e.need_admin}, 400)
                self._json({"ok": True, "message": "rule deleted"})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def log_message(self, *args):
        pass


def main():
    server = HTTPServer((HOST, PORT), Handler)
    admin = is_admin()
    print("=" * 50)
    print("  PortProxy GUI - http://{}:{}".format(HOST, PORT))
    print("=" * 50)
    if admin:
        print("  Admin: YES - add/delete available.")
    else:
        print("  Admin: NO - run as Administrator for add/delete.")
    print("=" * 50)
    threading.Timer(0.5, lambda: webbrowser.open("http://{}:{}".format(HOST, PORT))).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
