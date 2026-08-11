#!/usr/bin/env python3
"""PortProxy GUI - shared logic module (zero-dependency).

Extracted from portproxy_gui.pyw and server.py.  Both GUIs import this
instead of duplicating netsh wrappers, validation, i18n, CSV parsing,
WSL detection, firewall helpers, and admin detection.
"""

import csv
import ipaddress
import io
import os
import re
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from i18n import tr

# ── types ──

TYPES = ("v4tov4", "v4tov6", "v6tov4", "v6tov6")

# ── command log (shared across both GUIs) ──

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
        del CMD_LOG[: len(CMD_LOG) - CMD_LOG_MAX]


# ── netsh helpers ──


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
    """Run netsh interface portproxy command.  capture_output primary, shell redirect fallback."""
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
                "listenAddress": la,
                "listenPort": lp,
                "connectAddress": ca,
                "connectPort": cp,
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
        raise NetshError(_friendly_error(raw), need_admin=("提升" in raw or "elevation" in raw.lower()))


def export_rules():
    return list_rules()


def import_rules(rules):
    added, skipped = [], []
    for r in rules:
        rtype = str(r.get("type") or "v4tov4").strip().lower()
        if rtype not in TYPES:
            skipped.append(r)
            continue
        la = str(r.get("listenAddress") or "").strip()
        lp = str(r.get("listenPort") or "").strip()
        ca = str(r.get("connectAddress") or "").strip()
        cp = str(r.get("connectPort") or "").strip()
        ok, _ = validate_port(lp)
        if not ok:
            skipped.append(r)
            continue
        ok, _ = validate_ip(ca)
        if not ok:
            skipped.append(r)
            continue
        la_norm = la if la else "0.0.0.0"
        dup = False
        for ex in list_rules():
            exa = "0.0.0.0" if ex["listenAddress"] in ("", "*") else ex["listenAddress"]
            if ex.get("type") == rtype and exa == la_norm and ex["listenPort"] == lp:
                dup = True
                break
        if dup:
            skipped.append(r)
            continue
        try:
            do_netsh("add", la, lp, ca, cp, rtype=rtype)
            added.append(r)
        except Exception:
            skipped.append(r)
    return added, skipped


# ── validation ──


def validate_port(port_str):
    s = (port_str or "").strip()
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
    s = (ip_str or "").strip()
    if s in ("", "*"):
        return True, s
    try:
        addr = ipaddress.ip_address(s)
        return True, addr.compressed if addr.version == 6 else str(addr)
    except ValueError:
        if ":" in s:
            return False, tr("msg_addr_format6")
        return False, tr("msg_addr_format")


def _friendly_error(raw):
    if not raw:
        return tr("err_no_admin")
    low = raw.lower()
    if "elevation" in low or "提升" in raw:
        return tr("err_need_admin")
    if "already exists" in low or "已存在" in raw:
        return tr("err_exists")
    if "not found" in low or "找不到" in raw:
        return tr("err_not_found")
    if "parameter" in low:
        return tr("err_param", raw.strip())
    return raw.strip() or tr("err_generic")


# ── admin detection ──


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def relaunch_as_admin():
    import ctypes
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


# ── firewall helpers ──


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
    """Allow inbound TCP on a port.  Best-effort."""
    code, out, err = netsh_adv(["firewall", "add", "rule",
                                "name=" + name, "dir=in", "action=allow", "protocol=TCP",
                                "localport=" + str(port)])
    return code == 0


def fw_close(port, name):
    """Delete the inbound firewall rule we created.  Best-effort."""
    code, out, err = netsh_adv(["firewall", "delete", "rule", "name=" + name])
    return code == 0


# ── NetshError ──


class NetshError(Exception):
    def __init__(self, message, need_admin=False):
        super().__init__(message)
        self.message = message
        self.need_admin = need_admin


# ── WSL detection ──


def detect_wsl():
    """Detect WSL2 and return its IP.  Returns dict with available/wsl_ip/host_ip."""
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


# ── CSV parsing ──

CSV_HEADER = ["type", "listenaddress", "listenport", "connectaddress", "connectport"]


def parse_csv(text):
    """Parse CSV text into a list of rule dicts.  Returns (rules, errors)."""
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


# ── Port status detection (Task 2) ──

_IPHLPSVC_PID = None  # lazily cached


def _get_iphlpsvc_pid():
    """Return the PID of the iphlpsvc (IP Helper) service, or None."""
    global _IPHLPSVC_PID
    if _IPHLPSVC_PID is not None:
        return _IPHLPSVC_PID
    try:
        r = subprocess.run(["sc", "queryex", "iphlpsvc"], capture_output=True, timeout=10)
        out = _decode(r.stdout)
        m = re.search(r"PID\s*:\s*(\d+)", out)
        if m:
            _IPHLPSVC_PID = int(m.group(1))
        else:
            _IPHLPSVC_PID = False  # not found
    except Exception:
        _IPHLPSVC_PID = False
    return _IPHLPSVC_PID if _IPHLPSVC_PID else None


def _pid_name(pid):
    """Return the process name for a PID (e.g. 'nginx.exe')."""
    try:
        r = subprocess.run(["tasklist", "/FI", "PID eq " + str(pid), "/FO", "CSV", "/NH"],
                           capture_output=True, timeout=5)
        line = _decode(r.stdout).strip()
        if line:
            parts = line.split(",")
            if parts:
                return parts[0].strip('"')
        return "PID " + str(pid)
    except Exception:
        return "PID " + str(pid)


def _check_listen(port, timeout=2.0):
    """Check if *listenPort* is held by the IP Helper service.

    Returns ``"ok"`` or a dict ``{"error": "…"}``.
    """
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=timeout)
        out = _decode(r.stdout)
    except Exception as e:
        return {"error": "netstat 执行失败: {}".format(e)}

    port_str = ":" + str(port)
    matching = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        if "LISTENING" not in parts:
            continue
        # local address is the second column
        if port_str not in parts[1]:
            continue
        matching.append(parts)

    if not matching:
        return {"error": "端口 {} 未在监听（规则可能未生效）".format(port)}

    # Collect PIDs from matching lines
    pids = set()
    for parts in matching:
        try:
            pids.add(int(parts[-1]))
        except (ValueError, IndexError):
            pass

    iphlp_pid = _get_iphlpsvc_pid()
    if iphlp_pid and pids == {iphlp_pid}:
        return "ok"

    # Check if all PIDs are system processes (svchost, System, etc.)
    foreign_pids = []
    for pid in pids:
        if pid == 4:  # System process (PID 4)
            continue
        if iphlp_pid and pid == iphlp_pid:
            continue
        foreign_pids.append(pid)

    if not foreign_pids:
        return "ok"  # Only System + iphlpsvc → acceptable

    names = ", ".join(_pid_name(p) for p in foreign_pids[:3])
    return {"error": "端口 {} 被 {} 占用，规则被挤掉".format(port, names)}


def _check_connect(addr, port, timeout=2.0):
    """Test TCP connectivity to *(addr, port)*.

    Returns ``"ok"`` or a dict ``{"error": "…"}``.
    """
    if not addr or not port:
        return {"error": "缺少目标地址或端口"}
    import socket
    try:
        s = socket.create_connection((addr, int(port)), timeout=timeout)
        s.close()
        return "ok"
    except socket.timeout:
        return {"error": "连接超时 ({}s)".format(int(timeout))}
    except socket.gaierror:
        return {"error": "域名解析失败"}
    except OSError as e:
        errno = e.errno
        if errno in (111, 10061):  # ECONNREFUSED
            return {"error": "连接被拒绝（服务未启动）"}
        if errno in (101, 10051):  # ENETUNREACH
            return {"error": "网络不可达（主机离线？）"}
        return {"error": "连接失败: {}".format(e)}


def check_single_rule(rule, timeout=2.0):
    """Check one rule, return structured result dict.

    Result keys:
    - ``status`` – ``"ok"`` / ``"backend_down"`` / ``"listen_error"``
    - ``listen`` – ``"ok"`` or ``{"error": "…"}``
    - ``connect`` – ``"ok"`` or ``{"error": "…"}``
    - ``detail`` – human-readable multi-line string
    """
    result = {"status": "ok", "listen": "ok", "connect": "ok", "detail": ""}

    listen = _check_listen(rule["listenPort"], timeout)
    result["listen"] = listen
    if listen != "ok":
        result["status"] = "listen_error"

    connect = _check_connect(rule["connectAddress"], rule["connectPort"], timeout)
    result["connect"] = connect
    if connect != "ok" and result["status"] == "ok":
        result["status"] = "backend_down"

    # Build human-readable detail
    lines = []
    if result["listen"] == "ok":
        lines.append("监听正常")
    else:
        lines.append("监听异常: " + result["listen"]["error"])

    if result["connect"] == "ok":
        lines.append("目标可达")
    else:
        if result["status"] == "backend_down":
            lines.append("目标不可达: " + result["connect"]["error"])
        else:
            lines.append("目标: " + result["connect"]["error"])

    result["detail"] = "\n".join(lines)
    return result


def _rule_key(rule):
    """Return a hashable key for a rule dict."""
    return (rule["listenAddress"], rule["listenPort"], rule.get("type", "v4tov4"))


def check_rules(rules, timeout=2.0, max_workers=10):
    """Check all rules concurrently.

    Returns ``{key: result_dict, …}`` where *key* is the
    ``(listenAddress, listenPort, type)`` tuple.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {ex.submit(check_single_rule, r, timeout): _rule_key(r) for r in rules}
        for fut in as_completed(future_map):
            key = future_map[fut]
            try:
                results[key] = fut.result()
            except Exception as e:
                results[key] = {
                    "status": "listen_error",
                    "listen": {"error": str(e)},
                    "connect": "ok",
                    "detail": "检测异常: " + str(e),
                }
    return results