#!/usr/bin/env python3
"""PortProxy GUI - netsh portproxy graphical manager"""

import json, os, re, subprocess, sys, threading, webbrowser, tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler

HOST = "127.0.0.1"
PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
        raise RuntimeError((err or out).strip() or "operation failed")


class Handler(BaseHTTPRequestHandler):

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
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
                self._json({"ok": True, "rules": list_rules()})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def do_POST(self):
        try:
            data = self._body()
            if self.path == "/api/rules":
                if data.get("action") == "clear":
                    do_netsh("delete", "", "")
                    return self._json({"ok": True, "message": "cleared"})
                la = str(data.get("listenAddress") or "").strip()
                lp = str(data.get("listenPort") or "").strip()
                ca = str(data.get("connectAddress") or "").strip()
                cp = str(data.get("connectPort") or "").strip()
                if not lp or not ca:
                    raise ValueError("listenPort and connectAddress required")
                do_netsh("add", la, lp, ca, cp)
                self._json({"ok": True, "message": "rule added"})
            elif self.path == "/api/rules/delete":
                la = str(data.get("listenAddress") or "").strip()
                lp = str(data.get("listenPort") or "").strip()
                if not lp:
                    raise ValueError("listenPort required")
                do_netsh("delete", la, lp)
                self._json({"ok": True, "message": "rule deleted"})
            else:
                self._json({"error": "not found"}, 404)
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def log_message(self, *args):
        pass


def main():
    server = HTTPServer((HOST, PORT), Handler)
    print("=" * 50)
    print("  PortProxy GUI - http://{}:{}".format(HOST, PORT))
    print("=" * 50)
    print("  IMPORTANT: Admin rights needed for add/delete.")
    print("=" * 50)
    threading.Timer(0.5, lambda: webbrowser.open("http://{}:{}".format(HOST, PORT))).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
