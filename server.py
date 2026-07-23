#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy graphical manager (web backend)"""

import json, os, re, subprocess, threading, webbrowser, tempfile, ctypes, sys, time, csv, io
from datetime import datetime
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


TYPES = ("v4tov4", "v4tov6", "v6tov4", "v6tov6")

# ---- command log -------------------------------------------------------
CMD_LOG = []
CMD_LOG_MAX = 200

def _log_cmd(cmd_str, returncode, stdout, stderr):
    """Append a command execution record to CMD_LOG."""
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

# ---- CSV parsing -------------------------------------------------------

CSV_HEADER = ["type", "listenaddress", "listenport", "connectaddress", "connectport"]

def parse_csv(text):
    """Parse CSV text into a list of rule dicts. Returns (rules, errors)."""
    rules = []
    errors = []
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return rules, ["CSV 内容为空"]
    # validate header
    header = [h.strip().lower() for h in rows[0]]
    if header != CSV_HEADER:
        return rules, ["CSV 表头格式错误，应为: type,listenAddress,listenPort,connectAddress,connectPort"]
    for i, row in enumerate(rows[1:], start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if len(row) < 5:
            errors.append("第{}行: 字段数不足".format(i))
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
    """Detect WSL2 and return its IP. Returns dict with available/wsl_ip/host_ip."""
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
                # guess host IP (typically .1 on same subnet)
                parts = wsl_ip.rsplit(".", 1)
                if len(parts) == 2:
                    result["host_ip"] = parts[0] + ".1"
    except Exception:
        pass
    return result

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

def export_rules():
    return list_rules()

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
        for ex in export_rules():
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
                "protocol": "tcp",
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
            elif self.path == "/api/logs":
                self._json({"ok": True, "logs": CMD_LOG})
            elif self.path == "/api/wsl-detect":
                self._json({"ok": True, **detect_wsl()})
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
                rtype = str(data.get("type") or "v4tov4").strip().lower()
                if rtype not in TYPES:
                    return self._json({"ok": False, "error": "不支持的转发类型: " + rtype}, 400)
                firewall = bool(data.get("firewall"))
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
                # parse edit state first (needed for duplicate check)
                edit_type = str(data.get("editType") or "").strip().lower()
                edit_lp = str(data.get("editListenPort") or "").strip()
                edit_la = str(data.get("editListenAddress") or "").strip()
                edit_la_norm = edit_la if edit_la else "0.0.0.0"
                # duplicate check
                la_norm = la if la else "0.0.0.0"
                try:
                    existing = list_rules()
                    for r in existing:
                        ra = "0.0.0.0" if r["listenAddress"] in ("", "*") else r["listenAddress"]
                        if r.get("type") == rtype and ra == la_norm and r["listenPort"] == lp and not (edit_type == rtype and ra == edit_la_norm and r["listenPort"] == edit_lp):
                            return self._json(
                                {"ok": False, "error": "该规则已存在 ({}:{})".format(la_norm, lp),
                                 "duplicate": True}, 409)
                except Exception:
                    pass
                if edit_type and edit_lp:
                    try:
                        do_netsh("delete", edit_la_norm, edit_lp, rtype=edit_type)
                    except Exception:
                        pass
                try:
                    do_netsh("add", la, lp, ca, cp, rtype=rtype)
                    if firewall:
                        fw_open(lp, "PortProxy_%s_%s" % (rtype, lp))
                except NetshError as e:
                    return self._json({"ok": False, "error": e.message,
                                       "needAdmin": e.need_admin}, 400)
                self._json({"ok": True, "message": "rule added"})
            elif self.path == "/api/export":
                try:
                    rules = export_rules()
                    self._json({"ok": True, "rules": rules})
                except Exception as e:
                    self._json({"ok": False, "error": str(e)}, 400)
            elif self.path == "/api/import":
                fmt = str(data.get("format") or "json").strip().lower()
                if fmt == "csv":
                    csv_text = data.get("csv_text") or ""
                    if not csv_text.strip():
                        return self._json({"ok": False, "error": "CSV 内容为空"}, 400)
                    rules, csv_errors = parse_csv(csv_text)
                    if csv_errors and not rules:
                        return self._json({"ok": False, "error": csv_errors[0]}, 400)
                else:
                    rules = data.get("rules")
                    csv_errors = []
                    if not isinstance(rules, list):
                        return self._json({"ok": False, "error": "无效的规则列表"}, 400)
                try:
                    added, skipped = import_rules(rules)
                    resp = {"ok": True, "added": len(added), "skipped": len(skipped)}
                    if csv_errors:
                        resp["csv_errors"] = csv_errors
                    self._json(resp)
                except Exception as e:
                    self._json({"ok": False, "error": str(e)}, 400)
            elif self.path == "/api/logs/clear":
                CMD_LOG.clear()
                self._json({"ok": True, "message": "logs cleared"})
            elif self.path == "/api/elevate":
                ok = relaunch_as_admin()
                if ok:
                    self._json({"ok": True, "message": "elevating"})
                    threading.Timer(1.0, lambda: os._exit(0)).start()
                    return
                self._json({"ok": False, "error": "无法请求提权，请手动以管理员身份运行"}, 400)
            elif self.path == "/api/rules/delete":
                rtype = str(data.get("type") or "v4tov4").strip().lower()
                if rtype not in TYPES:
                    return self._json({"ok": False, "error": "不支持的转发类型: " + rtype}, 400)
                firewall = bool(data.get("firewall"))
                la = str(data.get("listenAddress") or "").strip()
                lp = str(data.get("listenPort") or "").strip()
                ok, res = validate_port(lp)
                if not ok:
                    return self._json({"ok": False, "error": res}, 400)
                try:
                    do_netsh("delete", la, lp, rtype=rtype)
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
    if os.environ.get("PP_NO_ELEVATE") != "1" and not is_admin():
        try:
            if relaunch_as_admin():
                sys.exit(0)
        except Exception:
            pass
    server = None
    for _ in range(20):
        try:
            server = HTTPServer((HOST, PORT), Handler)
            break
        except OSError:
            time.sleep(0.4)
    if server is None:
        print("无法绑定端口 %s:%d，请确认未被占用" % (HOST, PORT))
        sys.exit(1)
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
