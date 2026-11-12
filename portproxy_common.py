#!/usr/bin/env python3
"""PortProxy GUI - shared logic module (zero-dependency).

Extracted from portproxy_gui.pyw and server.py.  Both GUIs import this
instead of duplicating netsh wrappers, validation, i18n, CSV parsing,
WSL detection, firewall helpers, and admin detection.
"""

import csv
import io
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from i18n import tr

__version__ = "1.4.0"

# ── types ──

TYPES = ("v4tov4", "v4tov6", "v6tov4", "v6tov6")

# ── command log (shared across both GUIs) ──

CMD_LOG = []
CMD_LOG_MAX = 200
_CMD_LOG_LOCK = threading.Lock()


def _log_cmd(cmd_str, returncode, stdout, stderr):
    entry = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "cmd": cmd_str,
        "returncode": returncode,
        "stdout": (stdout or "").strip(),
        "stderr": (stderr or "").strip(),
    }
    with _CMD_LOG_LOCK:
        CMD_LOG.append(entry)
        if len(CMD_LOG) > CMD_LOG_MAX:
            del CMD_LOG[: len(CMD_LOG) - CMD_LOG_MAX]


# ── netsh helpers ──


def _decode(b):
    """Decode subprocess bytes robustly (Chinese Windows uses GBK/CP936).

    UTF-8 is tried first: GBK-encoded Chinese text is rarely valid UTF-8,
    whereas UTF-8 text whose bytes are valid GBK would otherwise be
    mis-decoded.  ASCII decodes identically under either codec.
    """
    if not b:
        return ""
    for enc in ("utf-8", "gbk", "cp936", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="replace")


def netsh(args: List[str]) -> Tuple[int, str, str]:
    """Run netsh interface portproxy command.  capture_output primary, temp-file redirect fallback."""
    cmd_str = "netsh interface portproxy " + " ".join(args)
    try:
        r = subprocess.run(
            ["netsh", "interface", "portproxy"] + args,
            capture_output=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        out = _decode(r.stdout)
        err = _decode(r.stderr)
        if r.returncode != 0 and not out and not err:
            return _netsh_file(args)
        _log_cmd(cmd_str, r.returncode, out, err)
        return r.returncode, out, err
    except subprocess.TimeoutExpired:
        _log_cmd(cmd_str, 1, "", "netsh 执行超时")
        return 1, "", "netsh 执行超时"
    except Exception:
        return _netsh_file(args)


def _netsh_file(args):
    """Fallback: redirect netsh output to a unique temp file without a shell."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix="portproxy_netsh_", suffix=".txt")
        # 全程复用 mkstemp 返回的句柄（w+b 读写），不关闭后按路径重开，
        # 消除临时文件被替换的 TOCTOU 窗口
        with os.fdopen(fd, "w+b") as f:
            r = subprocess.run(
                ["netsh", "interface", "portproxy"] + args,
                stdout=f,
                stderr=subprocess.STDOUT,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            f.seek(0)
            output = _decode(f.read())
        _log_cmd("netsh interface portproxy " + " ".join(args), r.returncode, output, "")
        return r.returncode, output, ""
    except Exception as e:
        return 1, "", str(e)
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def list_rules() -> List[Dict[str, str]]:
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


def do_netsh(op: str, listen_addr: str, listen_port: str, connect_addr: str = "",
             connect_port: str = "", rtype: str = "v4tov4") -> None:
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


def export_rules() -> List[Dict[str, str]]:
    return list_rules()


def rules_to_csv_text(rules: Iterable[Dict[str, str]]) -> str:
    """Serialize rules to CSV text (camelCase header, round-trips via parse_csv)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "listenAddress", "listenPort", "connectAddress", "connectPort"])
    for r in rules:
        writer.writerow([
            r.get("type", "v4tov4"),
            r.get("listenAddress", ""),
            r.get("listenPort", ""),
            r.get("connectAddress", ""),
            r.get("connectPort", ""),
        ])
    return buf.getvalue()


def import_rules(rules: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    added, skipped = [], []
    existing = list_rules()
    existing_norm = [
        (ex.get("type"), normalize_addr(ex.get("listenAddress", "")), str(ex.get("listenPort", "")))
        for ex in existing
    ]
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
        ok, _ = validate_connect_ip(ca)
        if not ok:
            skipped.append(r)
            continue
        la_norm = normalize_addr(la)
        dup = any(t == rtype and a == la_norm and p == lp for t, a, p in existing_norm)
        if dup:
            skipped.append(r)
            continue
        try:
            do_netsh("add", la, lp, ca, cp, rtype=rtype)
            added.append(r)
            existing_norm.append((rtype, la_norm, lp))
        except Exception:
            skipped.append(r)
    return added, skipped


# ── validation ──


def validate_port(port_str: str) -> Tuple[bool, Union[int, str]]:
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


def _ip_or_none(s):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def validate_ip(ip_str: str) -> Tuple[bool, str]:
    """Validate a listen address: empty or '*' (wildcard) or a valid IP."""
    s = (ip_str or "").strip()
    if s in ("", "*"):
        return True, s
    addr = _ip_or_none(s)
    if addr is None:
        if ":" in s:
            return False, tr("msg_addr_format6")
        return False, tr("msg_addr_format")
    return True, addr.compressed if addr.version == 6 else str(addr)


def validate_connect_ip(ip_str: str) -> Tuple[bool, str]:
    """Validate a connect (target) address: required, non-wildcard IP."""
    s = (ip_str or "").strip()
    if not s:
        return False, tr("msg_input_target")
    if s == "*":
        return False, tr("msg_addr_format")
    addr = _ip_or_none(s)
    if addr is None:
        if ":" in s:
            return False, tr("msg_addr_format6")
        return False, tr("msg_addr_format")
    return True, addr.compressed if addr.version == 6 else str(addr)


def normalize_addr(addr: str) -> str:
    """Normalize a listen address so '*', '' and '0.0.0.0' compare equal."""
    a = (addr or "").strip()
    if a in ("", "*"):
        return "0.0.0.0"
    return a


def find_duplicate(rules: List[Dict[str, str]], rtype: str, la: str, lp: str,
                   exclude: Optional[Tuple[str, str, str]] = None) -> Optional[Dict[str, str]]:
    """Return the first existing rule conflicting with (rtype, la, lp), or None.

    ``exclude`` is an optional ``(rtype, listen_addr, listen_port)`` tuple that
    should be ignored (used while editing the rule at that listen point).
    """
    la_norm = normalize_addr(la)
    for r in rules:
        if r.get("type") != rtype:
            continue
        if str(r.get("listenPort", "")) != str(lp):
            continue
        if normalize_addr(r.get("listenAddress", "")) != la_norm:
            continue
        if exclude is not None:
            ex_type, ex_la, ex_lp = exclude
            if (r.get("type") == ex_type
                    and normalize_addr(r.get("listenAddress", "")) == normalize_addr(ex_la)
                    and str(r.get("listenPort", "")) == str(ex_lp)):
                continue
        return r
    return None


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


# ── rule mutation helpers ──


def add_or_replace(listen_addr: str, listen_port: str, connect_addr: str, connect_port: str,
                   rtype: str, edit_type: Optional[str] = None,
                   edit_listen_addr: Optional[str] = None,
                   edit_listen_port: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Add a rule, replacing an existing rule identified by ``edit_*``.

    Sequencing with rollback so a failed edit never loses the original rule:
    - different listen point: add new first, then delete the old rule.
    - same listen point: delete old, add new; on failure re-add the old rule.

    Returns the old rule dict if one was replaced, else None.
    Raises NetshError on failure (rollback already attempted).
    """
    edit_la_norm = normalize_addr(edit_listen_addr) if edit_listen_addr else "0.0.0.0"
    new_la_norm = normalize_addr(listen_addr)
    same_point = (
        edit_type == rtype
        and edit_listen_port is not None
        and str(edit_listen_port) == str(listen_port)
        and edit_la_norm == new_la_norm
    )

    old_rule = None
    if edit_type and edit_listen_port:
        for r in list_rules():
            if (r.get("type") == edit_type
                    and str(r.get("listenPort", "")) == str(edit_listen_port)
                    and normalize_addr(r.get("listenAddress", "")) == edit_la_norm):
                old_rule = r
                break

    if old_rule is None:
        do_netsh("add", listen_addr, listen_port, connect_addr, connect_port, rtype=rtype)
        return None

    old_la = old_rule.get("listenAddress", "")
    if same_point:
        do_netsh("delete", old_la, old_rule.get("listenPort", ""),
                 rtype=old_rule.get("type", "v4tov4"))
        try:
            do_netsh("add", listen_addr, listen_port, connect_addr, connect_port, rtype=rtype)
        except Exception:
            try:
                do_netsh("add", old_la, old_rule.get("listenPort", ""),
                         old_rule.get("connectAddress", ""), old_rule.get("connectPort", ""),
                         rtype=old_rule.get("type", "v4tov4"))
            except Exception:
                pass
            raise
    else:
        do_netsh("add", listen_addr, listen_port, connect_addr, connect_port, rtype=rtype)
        try:
            do_netsh("delete", old_la, old_rule.get("listenPort", ""),
                     rtype=old_rule.get("type", "v4tov4"))
        except Exception:
            pass  # new rule is in place; the old one may linger - caller is informed via return
    return old_rule


def clear_all_rules() -> int:
    """Delete every portproxy rule (best-effort).  Returns the number deleted."""
    rules = list_rules()
    count = 0
    for r in rules:
        try:
            do_netsh("delete", r.get("listenAddress", ""), r.get("listenPort", ""),
                     rtype=r.get("type", "v4tov4"))
            fw_close_by_rule(r)
            count += 1
        except Exception:
            pass
    return count


# ── admin detection ──


def is_admin() -> Optional[bool]:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def relaunch_as_admin(target: Optional[str] = None) -> bool:
    import ctypes
    try:
        if getattr(sys, "frozen", False):
            exe, params = sys.executable, ""
        else:
            exe = sys.executable
            script = target
            if not script:
                script = sys.argv[0] if (sys.argv and sys.argv[0]) else __file__
            script = os.path.abspath(script)
            if os.path.exists(script):
                params = subprocess.list2cmdline([script] + list(sys.argv[1:]))
            else:
                params = ""
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return ret > 32
    except Exception:
        return False


# ── firewall helpers ──


def netsh_adv(args: List[str]) -> Tuple[int, str, str]:
    """Run a netsh advfirewall command."""
    cmd_str = "netsh advfirewall " + " ".join(args)
    try:
        r = subprocess.run(["netsh", "advfirewall"] + args, capture_output=True, timeout=60,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out, err = _decode(r.stdout), _decode(r.stderr)
        _log_cmd(cmd_str, r.returncode, out, err)
        return r.returncode, out, err
    except Exception as e:
        _log_cmd(cmd_str, 1, "", str(e))
        return 1, "", str(e)


def fw_rule_name(rtype: str, listen_addr: str, listen_port: str) -> str:
    """Deterministic firewall rule name that includes the listen address."""
    la = normalize_addr(listen_addr).replace(".", "_").replace(":", "_")
    return "PortProxy_{}_{}_{}".format(rtype, la, listen_port)


def fw_open(port: str, name: str) -> bool:
    """Allow inbound TCP on a port.  Best-effort."""
    code, out, err = netsh_adv(["firewall", "add", "rule",
                                "name=" + name, "dir=in", "action=allow", "protocol=TCP",
                                "localport=" + str(port)])
    return code == 0


def fw_close(port: str, name: str) -> bool:
    """Delete the inbound firewall rule we created.  Best-effort."""
    code, out, err = netsh_adv(["firewall", "delete", "rule", "name=" + name])
    return code == 0


def fw_close_by_rule(rule: Dict[str, str]) -> None:
    """Delete the inbound firewall rule associated with a portproxy rule."""
    try:
        fw_close(rule.get("listenPort", ""),
                 fw_rule_name(rule.get("type", "v4tov4"), rule.get("listenAddress", ""),
                              rule.get("listenPort", "")))
    except Exception:
        pass


# ── NetshError ──


class NetshError(Exception):
    def __init__(self, message, need_admin=False):
        super().__init__(message)
        self.message = message
        self.need_admin = need_admin


# ── WSL detection ──


def detect_wsl() -> Dict[str, Any]:
    """Detect WSL2 and return its IP.  Returns dict with available/wsl_ip/host_ip."""
    result = {"available": False, "wsl_ip": "", "host_ip": ""}
    try:
        r = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
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


def parse_csv(text: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """Parse CSV text into a list of rule dicts.  Returns (rules, errors).

    The header is matched by column name (case-insensitive), so column order
    and extra columns are tolerated.
    """
    rules = []
    errors = []
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return rules, [tr("csv_empty")]
    header = [h.strip().lower() for h in rows[0]]
    colmap = {name: idx for idx, name in enumerate(header)}
    required = ["type", "listenaddress", "listenport", "connectaddress", "connectport"]
    if any(name not in colmap for name in required):
        return rules, [tr("csv_header_err")]
    for i, row in enumerate(rows[1:], start=2):
        if not row or all(c.strip() == "" for c in row):
            continue
        if any(colmap[name] >= len(row) for name in required):
            errors.append(tr("csv_field_err", i))
            continue
        rules.append({
            "type": row[colmap["type"]].strip(),
            "listenAddress": row[colmap["listenaddress"]].strip(),
            "listenPort": row[colmap["listenport"]].strip(),
            "connectAddress": row[colmap["connectaddress"]].strip(),
            "connectPort": row[colmap["connectport"]].strip(),
        })
    return rules, errors


# ── Port status detection ──

_IPHLPSVC_PID = None
_IPHLPSVC_PID_TS = 0.0
_MISSING = object()


def _get_iphlpsvc_pid():
    """Return the PID of the iphlpsvc (IP Helper) service, or None.

    The result is cached for 30 seconds (the service may be restarted).
    """
    global _IPHLPSVC_PID, _IPHLPSVC_PID_TS
    now = time.time()
    if _IPHLPSVC_PID is not None and now - _IPHLPSVC_PID_TS < 30:
        return _IPHLPSVC_PID if _IPHLPSVC_PID else None
    _IPHLPSVC_PID_TS = now
    try:
        r = subprocess.run(["sc", "queryex", "iphlpsvc"], capture_output=True, timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        out = _decode(r.stdout)
        m = re.search(r"PID\s*:\s*(\d+)", out)
        _IPHLPSVC_PID = int(m.group(1)) if m else False
    except Exception:
        _IPHLPSVC_PID = False
    return _IPHLPSVC_PID if _IPHLPSVC_PID else None


def _pid_name(pid):
    """Return the process name for a PID (e.g. 'nginx.exe')."""
    try:
        r = subprocess.run(["tasklist", "/FI", "PID eq " + str(pid), "/FO", "CSV", "/NH"],
                           capture_output=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        line = _decode(r.stdout).strip()
        if line:
            parts = line.split(",")
            if parts:
                return parts[0].strip('"')
        return "PID " + str(pid)
    except Exception:
        return "PID " + str(pid)


def _extract_port(local_addr):
    """Extract the port number from a netstat local address (0.0.0.0:8080 or [::]:8080)."""
    if not local_addr:
        return None
    if local_addr.startswith("["):
        end = local_addr.find("]")
        if end == -1:
            return None
        port_str = local_addr[end + 1:]
    else:
        if ":" not in local_addr:
            return None
        port_str = local_addr.rsplit(":", 1)[1]
    port_str = port_str.lstrip(":")
    try:
        return int(port_str)
    except ValueError:
        return None


def parse_netstat_listen(output):
    """Parse ``netstat -ano`` output into {port: set(pids)} for LISTENING sockets."""
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or "LISTENING" not in parts:
            continue
        port = _extract_port(parts[1])
        if port is None:
            continue
        try:
            pid = int(parts[-1])
        except (ValueError, IndexError):
            continue
        result.setdefault(port, set()).add(pid)
    return result


def _run_netstat(timeout=5.0):
    try:
        r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return _decode(r.stdout)
    except Exception:
        return ""


def _check_listen(port, listen_map, iphlp_pid):
    """Check if *listenPort* is held by the IP Helper service.

    Returns ``"ok"`` or a dict ``{"error": "…"}``.
    """
    pids = listen_map.get(int(port), set())
    if not pids:
        return {"error": tr("st_listen_not", port)}

    if iphlp_pid and pids == {iphlp_pid}:
        return "ok"

    foreign_pids = [p for p in pids if p != 4 and p != iphlp_pid]
    if not foreign_pids:
        return "ok"  # Only System + iphlpsvc → acceptable

    names = ", ".join(_pid_name(p) for p in sorted(foreign_pids)[:3])
    return {"error": tr("st_occupied", port, names)}


def _check_connect(addr, port, timeout=2.0):
    """Test TCP connectivity to *(addr, port)*.

    Returns ``"ok"`` or a dict ``{"error": "…"}``.
    """
    if not addr or not port:
        return {"error": tr("st_missing_target")}
    import socket
    try:
        s = socket.create_connection((addr, int(port)), timeout=timeout)
        s.close()
        return "ok"
    except socket.timeout:
        return {"error": tr("st_conn_timeout", int(timeout))}
    except socket.gaierror:
        return {"error": tr("st_conn_dns")}
    except OSError as e:
        errno = e.errno
        if errno in (111, 10061):  # ECONNREFUSED
            return {"error": tr("st_conn_refused")}
        if errno in (101, 10051):  # ENETUNREACH
            return {"error": tr("st_conn_unreach")}
        return {"error": tr("st_conn_fail", e)}


def check_single_rule(rule: Dict[str, str], timeout: float = 2.0,
                      listen_map: Optional[Dict[int, set]] = None,
                      iphlp_pid: Any = _MISSING) -> Dict[str, Any]:
    """Check one rule, return structured result dict.

    Result keys:
    - ``status`` – ``"ok"`` / ``"backend_down"`` / ``"listen_error"``
    - ``listen`` – ``"ok"`` or ``{"error": "…"}``
    - ``connect`` – ``"ok"`` or ``{"error": "…"}``
    - ``detail`` – human-readable multi-line string
    """
    if listen_map is None:
        listen_map = parse_netstat_listen(_run_netstat(timeout))
    if iphlp_pid is _MISSING:
        iphlp_pid = _get_iphlpsvc_pid()

    result = {"status": "ok", "listen": "ok", "connect": "ok", "detail": ""}

    listen = _check_listen(rule["listenPort"], listen_map, iphlp_pid)
    result["listen"] = listen
    if listen != "ok":
        result["status"] = "listen_error"

    connect = _check_connect(rule["connectAddress"], rule["connectPort"], timeout)
    result["connect"] = connect
    if connect != "ok" and result["status"] == "ok":
        result["status"] = "backend_down"

    lines = []
    if result["listen"] == "ok":
        lines.append(tr("st_listen_ok"))
    else:
        lines.append(tr("st_listen_err", result["listen"]["error"]))

    if result["connect"] == "ok":
        lines.append(tr("st_conn_ok"))
    else:
        if result["status"] == "backend_down":
            lines.append(tr("st_conn_down", result["connect"]["error"]))
        else:
            lines.append(tr("st_target", result["connect"]["error"]))

    result["detail"] = "\n".join(lines)
    return result


def _rule_key(rule):
    """Return a hashable key for a rule dict."""
    return (rule["listenAddress"], rule["listenPort"], rule.get("type", "v4tov4"))


def check_rules(rules: List[Dict[str, str]], timeout: float = 2.0,
                max_workers: int = 10) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """Check all rules concurrently.

    ``netstat -ano`` is run once and its result is shared by every rule.
    Returns ``{key: result_dict, …}`` where *key* is the
    ``(listenAddress, listenPort, type)`` tuple.
    """
    listen_map = parse_netstat_listen(_run_netstat(timeout))
    iphlp_pid = _get_iphlpsvc_pid()
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {
            ex.submit(check_single_rule, r, timeout, listen_map, iphlp_pid): _rule_key(r)
            for r in rules
        }
        for fut in as_completed(future_map):
            key = future_map[fut]
            try:
                results[key] = fut.result()
            except Exception as e:
                results[key] = {
                    "status": "listen_error",
                    "listen": {"error": str(e)},
                    "connect": "ok",
                    "detail": tr("st_check_fail", e),
                }
    return results
