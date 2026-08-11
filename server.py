#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy graphical manager (web backend)"""

import json, os, subprocess, threading, webbrowser, ctypes, sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from portproxy_common import (
    TYPES, CMD_LOG, _log_cmd,
    netsh, list_rules, do_netsh, export_rules, import_rules,
    validate_port, validate_ip, is_admin, _friendly_error,
    NetshError, detect_wsl, relaunch_as_admin,
    netsh_adv, fw_open, fw_close, parse_csv, CSV_HEADER,
    check_rules, check_single_rule,
)

HOST = "127.0.0.1"
PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
            elif self.path == "/api/check":
                rules = list_rules()
                status_map = check_rules(rules)
                self._json({"ok": True, "status": status_map})
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
            server = ThreadingHTTPServer((HOST, PORT), Handler)
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
