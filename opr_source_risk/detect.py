"""Static detectors used by bundled checks. Confidence is ast or config."""

from __future__ import annotations

import ast
import re
from typing import Any

Finding = dict[str, Any]

ALL_HOSTS = {"0.0.0.0", "::", "*", "[::]"}


def _finding(
    facet: str,
    title: str,
    *,
    line: int,
    evidence: str,
    confidence: str,
    severity: str = "high",
    path: str = "",
) -> Finding:
    return {
        "facet": facet,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "path": path,
        "line": line,
        "evidence": evidence.strip()[:240],
    }


def python_bind_all(text: str, path: str = "") -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if name != "bind" or not node.args:
                self.generic_visit(node)
                return
            arg = node.args[0]
            host = None
            if isinstance(arg, ast.Tuple) and arg.elts:
                el0 = arg.elts[0]
                if isinstance(el0, ast.Constant) and isinstance(el0.value, str):
                    host = el0.value
            elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                host = arg.value
            if host in ALL_HOSTS or host == "":
                line = text.splitlines()[node.lineno - 1] if node.lineno else ""
                out.append(
                    _finding(
                        "net.listen-all",
                        "Binds or listens on all interfaces",
                        line=node.lineno or 0,
                        evidence=line,
                        confidence="ast",
                        path=path,
                    )
                )
            self.generic_visit(node)

    V().visit(tree)
    return out


def python_bind_privileged(text: str, path: str = "") -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    out: list[Finding] = []

    class V(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name != "bind" or not node.args:
                self.generic_visit(node)
                return
            arg = node.args[0]
            port = None
            if isinstance(arg, ast.Tuple) and len(arg.elts) >= 2:
                el1 = arg.elts[1]
                if isinstance(el1, ast.Constant) and isinstance(el1.value, int):
                    port = el1.value
            if port is not None and 0 < port < 1024:
                line = text.splitlines()[node.lineno - 1] if node.lineno else ""
                out.append(
                    _finding(
                        "net.listen-privileged-port",
                        "Listens on a privileged port",
                        line=node.lineno or 0,
                        evidence=line,
                        confidence="ast",
                        path=path,
                    )
                )
            self.generic_visit(node)

    V().visit(tree)
    return out


_LISTEN_STREAM = re.compile(
    r"^(ListenStream|ListenDatagram|ListenSequentialPacket)\s*=\s*(.+)$",
    re.I,
)


def systemd_listen(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _LISTEN_STREAM.match(line.strip())
        if not m:
            continue
        spec = m.group(2).strip()
        host, port = _split_hostport(spec)
        if _is_all_host(host, spec):
            out.append(
                _finding(
                    "net.listen-all",
                    "Binds or listens on all interfaces",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
        if port is not None and 0 < port < 1024:
            out.append(
                _finding(
                    "net.listen-privileged-port",
                    "Listens on a privileged port",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
    return out


_NGINX_LISTEN = re.compile(r"^\s*listen\s+([^;]+);", re.I)


def nginx_listen(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _NGINX_LISTEN.search(line)
        if not m:
            continue
        spec = m.group(1).strip().split()[0]
        host, port = _split_hostport(spec)
        if host is None and port is not None:
            host = "0.0.0.0"
        if _is_all_host(host, spec):
            out.append(
                _finding(
                    "net.listen-all",
                    "Binds or listens on all interfaces",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
        if port is not None and 0 < port < 1024:
            out.append(
                _finding(
                    "net.listen-privileged-port",
                    "Listens on a privileged port",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
    return out


def compose_ports(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None
    ports: list[tuple[int, str]] = []
    if yaml is not None:
        try:
            data = yaml.safe_load(text) or {}
        except Exception:
            data = {}
        services = data.get("services") if isinstance(data, dict) else None
        if isinstance(services, dict):
            for svc in services.values():
                if not isinstance(svc, dict):
                    continue
                for p in svc.get("ports") or []:
                    ports.append((0, str(p)))
    if not ports:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"ports\s*:", line):
                continue
            m = re.search(r"[\"']([^\"']+:\d+(?::\d+)?)[\"']", line)
            if m:
                ports.append((i, m.group(1)))
    if yaml is not None and ports and ports[0][0] == 0:
        # recover line numbers from text
        numbered: list[tuple[int, str]] = []
        for spec in [p[1] for p in ports]:
            line_no = 1
            for i, line in enumerate(text.splitlines(), 1):
                if spec in line:
                    line_no = i
                    break
            numbered.append((line_no, spec))
        ports = numbered
    for line_no, spec in ports:
        host, port = _split_hostport(spec.split("/")[0])
        # compose "8080:80" publishes on all interfaces
        raw = spec.strip()
        if raw.startswith("127.0.0.1") or raw.startswith("localhost"):
            continue
        if host in ALL_HOSTS or host in (None, ""):
            line = text.splitlines()[line_no - 1] if line_no else spec
            out.append(
                _finding(
                    "net.listen-all",
                    "Binds or listens on all interfaces",
                    line=line_no,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
        pub = spec.split(":")
        # host:hostPort:containerPort or hostPort:containerPort
        try:
            if len(pub) == 3:
                hp = int(pub[1])
            elif len(pub) == 2:
                hp = int(pub[0])
            else:
                hp = port or 0
        except ValueError:
            hp = port or 0
        if 0 < hp < 1024:
            line = text.splitlines()[line_no - 1] if line_no else spec
            out.append(
                _finding(
                    "net.listen-privileged-port",
                    "Listens on a privileged port",
                    line=line_no,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
    return out


def _split_hostport(spec: str) -> tuple[str | None, int | None]:
    spec = spec.strip().strip("\"'")
    spec = spec.split()[0] if spec else spec
    if spec.startswith("[") and "]:" in spec:
        host, _, rest = spec[1:].partition("]:")
        try:
            return host, int(re.match(r"\d+", rest).group()) if re.match(r"\d+", rest) else None
        except (ValueError, AttributeError):
            return host, None
    if spec.count(":") >= 1 and not spec.startswith("["):
        parts = spec.split(":")
        # host:port or host:hostPort:containerPort
        if len(parts) >= 2 and re.match(r"\d+$", parts[-1] or ""):
            if len(parts) >= 3 and re.match(r"\d+$", parts[-2] or ""):
                host = ":".join(parts[:-2]) or None
                try:
                    return host, int(parts[-2])
                except ValueError:
                    return host, None
            host = parts[0] or None
            try:
                return host, int(parts[-1])
            except ValueError:
                return host, None
    if spec.isdigit():
        return None, int(spec)
    return spec or None, None


def _is_all_host(host: str | None, spec: str) -> bool:
    if host in ALL_HOSTS or host == "":
        return True
    if host is None and re.fullmatch(r"\d+", spec.strip().strip("\"'").split()[0]):
        return True
    return False


_CHMOD_777 = re.compile(r"chmod\s+(?:-R\s+)?(?:0)?777\b")
_CURL_PIPE = re.compile(r"curl\s+[^\n|]*\|\s*(ba)?sh")


def chmod_world(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _CHMOD_777.search(line):
            out.append(
                _finding(
                    "fs.world-writable",
                    "chmod 777 makes a path world-writable",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def curl_pipe_shell(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _CURL_PIPE.search(line):
            out.append(
                _finding(
                    "install.curl-pipe-shell",
                    "Bootstrap pipes curl into a shell",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


_USER_ROOT = re.compile(r"^User\s*=\s*root\s*$", re.I | re.M)
_DYNAMIC_USER = re.compile(r"^DynamicUser\s*=\s*yes\s*$", re.I | re.M)
_PRIVILEGED = re.compile(r"privileged\s*:\s*true", re.I)
_DOCKER_SOCK = re.compile(r"/var/run/docker\.sock")
_HOST_PID = re.compile(r"hostPID\s*:\s*true|pid:\s*host", re.I)
_HOST_NET = re.compile(r"hostNetwork\s*:\s*true|network_mode\s*:\s*[\"']?host", re.I)
_CAP_SYS_ADMIN = re.compile(r"SYS_ADMIN|CAP_SYS_ADMIN")
_SETCAP = re.compile(r"\bsetcap\b")
_SETUID = re.compile(r"chmod\s+(?:u\+s|4755|4751|4711)\b")
_DEBUG = re.compile(
    r"\b(DEBUG|APP_DEBUG)\s*[=:]\s*(True|true|1)\b|pprof\.Start|gin\.SetMode\(\s*gin\.DebugMode"
)
_WEAK = re.compile(
    r"(SECRET|PASSWORD|TOKEN|JWT)[A-Z0-9_]*\s*[=:]\s*[\"']?(changeme|password|secret|admin|1234)?[\"']?\s*$",
    re.I,
)
_SENSITIVE = re.compile(
    r"(install|cp|mv|tee|cat\s*>)\s+[^\n]*(/etc/|/root/|/usr/|/boot/)"
)
_METRICS_ROUTE = re.compile(
    r"""@(?:app|bp|router)\.route\(\s*[\"'](/metrics|/debug|/admin|/pprof)"""
)
_AUTH_HINT = re.compile(r"login_required|require_auth|Authorization|auth_required|Depends\(\s*auth", re.I)
_SYSTEMD_INSTALL = re.compile(
    r"systemd/system/[^\"'\s]+\.service|usr/lib/systemd"
)
_SYSTEMD_SOCKET = re.compile(
    r"systemd/system/[^\"'\s]+\.socket|ListenStream\s*="
)
_UPNP = re.compile(
    r"\bminiupnpc\b|\bnatpmp\b|\bNAT-PMP\b|\bUPnP\b|\bholepunch\b|\bIGD\b",
    re.I,
)
_FIREWALL_OPEN = re.compile(
    r"iptables\s+.*\s-j\s+ACCEPT|ufw\s+allow|firewall-cmd\s+.*--add-port",
    re.I,
)
_TELEMETRY = re.compile(
    r"sentry_sdk\.init|SENTRY_DSN|TELEMETRY_ENABLED\s*=\s*True|crashlytics|mixpanel|segment\.init",
    re.I,
)
_USER_ROUTE = re.compile(
    r"""@(?:app|bp|router)\.route\(\s*[\"'](/(?!admin(?:/|$)|debug(?:/|$)|metrics(?:/|$)|pprof)[^\"']*)[\"']"""
)
_CONTROL_ROUTE = re.compile(
    r"""@(?:app|bp|router)\.route\(\s*[\"'](/(?:admin|debug|metrics|pprof)[^\"']*)[\"']"""
)
_ADMIN_BIND = re.compile(r"\badmin_(?:db_url|token|key|secret|password)\s*=\s*(\S+)", re.I)
_TENANT_BIND = re.compile(r"\b(?:tenant|user|app)_(?:db_url|token|key|secret|password)\s*=\s*(\S+)", re.I)
_TMP_FIXED = re.compile(r"""(?:Path|open|bind)\(\s*[\"']/tmp/[^\"']+[\"']""")
_INSECURE_TLS = re.compile(r"InsecureSkipVerify\s*[:=]\s*true|ssl_verify\s*[:=]\s*false|verify\s*=\s*False", re.I)
_NGINX_ADMIN = re.compile(r"location\s+/admin", re.I)
_NGINX_LISTEN80 = re.compile(r"listen\s+80\b", re.I)
_NGINX_SSL = re.compile(r"listen\s+443|ssl\s+on", re.I)
_HTTPS_SOURCE = re.compile(r"https?://[^\s\"')]+")


def root_service(text: str, path: str = "") -> list[Finding]:
    if not path.endswith(".service"):
        return []
    if _USER_ROOT.search(text) and not _DYNAMIC_USER.search(text):
        for i, line in enumerate(text.splitlines(), 1):
            if _USER_ROOT.match(line.strip()):
                return [
                    _finding(
                        "priv.root-service",
                        "systemd unit runs as root",
                        line=i,
                        evidence=line,
                        confidence="config",
                        path=path,
                    )
                ]
    return []


def container_escape(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _PRIVILEGED.search(line) or _DOCKER_SOCK.search(line) or _HOST_PID.search(line) or (
            _HOST_NET.search(line) and "ports" not in line
        ) or _CAP_SYS_ADMIN.search(line):
            out.append(
                _finding(
                    "priv.container-escape",
                    "Container config allows host escape or host network/pid",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
    return out


def setuid_or_caps(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _SETCAP.search(line) or _SETUID.search(line):
            out.append(
                _finding(
                    "priv.setuid-or-caps",
                    "setuid bit or extra file capabilities",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def debug_in_release(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if _DEBUG.search(line):
            out.append(
                _finding(
                    "plane.debug-in-release",
                    "Debug mode or pprof enabled in non-example config",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                    severity="medium",
                )
            )
    return out


def weak_default_secret(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = _WEAK.search(line)
        if not m:
            continue
        val = (m.group(2) or "").lower()
        if val in {"", "changeme", "password", "secret", "admin", "1234"}:
            out.append(
                _finding(
                    "secret.weak-default",
                    "Weak or placeholder secret in config",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def sensitive_write(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if "$pkgdir" in line:
            continue
        if _SENSITIVE.search(line):
            out.append(
                _finding(
                    "fs.sensitive-write",
                    "Install or copy into a sensitive host path",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def unauth_control_route(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not _METRICS_ROUTE.search(line):
            continue
        window = "\n".join(lines[i : i + 12])
        if _AUTH_HINT.search(window):
            continue
        out.append(
            _finding(
                "plane.unauth-control",
                "Control/debug/metrics route has no nearby auth",
                line=i + 1,
                evidence=line,
                confidence="heuristic",
                path=path,
                severity="medium",
            )
        )
    return out


def lingering_systemd_unit(files: dict[str, str]) -> list[Finding]:
    """files: relative path -> text. Join install vs remove."""
    installs: list[tuple[str, int, str]] = []
    removes = False
    for path, text in files.items():
        name = path.lower()
        if name.endswith(".install") or "post_remove" in name or "pre_remove" in name:
            if re.search(r"systemctl|systemd|\.service", text, re.I):
                removes = True
        for i, line in enumerate(text.splitlines(), 1):
            if _SYSTEMD_INSTALL.search(line):
                installs.append((path, i, line))
        if re.search(r"^remove\(\)|post_remove", text, re.M) and re.search(
            r"systemd|\.service", text
        ):
            removes = True
    if removes:
        return []
    return [
        _finding(
            "persist.lingering-unit",
            "systemd unit is installed with no matching remove",
            line=line,
            evidence=evidence,
            confidence="config",
            path=path,
        )
        for path, line, evidence in installs
    ]


def unsigned_fetch(text: str, path: str = "") -> list[Finding]:
    if not path.endswith("PKGBUILD") and "PKGBUILD" not in path:
        return []
    sources = _HTTPS_SOURCE.findall(text)
    if not sources:
        return []
    skip = bool(re.search(r"sha256sums\s*=\s*\([^\)]*SKIP", text, re.S | re.I))
    missing = not re.search(r"sha256sums\s*=", text, re.I) and not re.search(
        r"b2sums\s*=", text, re.I
    )
    if not skip and not missing:
        return []
    for i, line in enumerate(text.splitlines(), 1):
        if "source=" in line or "https://" in line:
            return [
                _finding(
                    "install.unsigned-fetch",
                    "Remote source with SKIP or missing checksums",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            ]
    return []


def plaintext_control(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    if _NGINX_LISTEN80.search(text) and _NGINX_ADMIN.search(text) and not _NGINX_SSL.search(text):
        for i, line in enumerate(text.splitlines(), 1):
            if _NGINX_ADMIN.search(line) or _NGINX_LISTEN80.search(line):
                out.append(
                    _finding(
                        "net.plaintext-control",
                        "Control plane served over plaintext HTTP",
                        line=i,
                        evidence=line,
                        confidence="config",
                        path=path,
                    )
                )
                break
    for i, line in enumerate(text.splitlines(), 1):
        if _INSECURE_TLS.search(line):
            out.append(
                _finding(
                    "net.plaintext-control",
                    "TLS verification disabled on a client/server",
                    line=i,
                    evidence=line,
                    confidence="config",
                    path=path,
                )
            )
    return out


def upnp_or_holepunch(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _UPNP.search(line):
            out.append(
                _finding(
                    "net.upnp-or-holepunch",
                    "UPnP, NAT-PMP, or hole punching",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def firewall_open(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _FIREWALL_OPEN.search(line):
            out.append(
                _finding(
                    "net.firewall-open",
                    "Firewall rule opens inbound traffic",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                )
            )
    return out


def outbound_unexpected(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _TELEMETRY.search(line):
            out.append(
                _finding(
                    "net.outbound-unexpected",
                    "Default-on telemetry or crash reporter",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                    severity="medium",
                )
            )
    return out


def shared_listener(text: str, path: str = "") -> list[Finding]:
    user = _USER_ROUTE.search(text)
    control = _CONTROL_ROUTE.search(text)
    if not (user and control):
        return []
    line = text[: control.start()].count("\n") + 1
    return [
        _finding(
            "plane.shared-listener",
            "User traffic and control routes share one listener",
            line=line,
            evidence=control.group(0),
            confidence="heuristic",
            path=path,
            severity="medium",
        )
    ]


def shared_credentials(text: str, path: str = "") -> list[Finding]:
    admins = {m.group(1).rstrip(",") for m in _ADMIN_BIND.finditer(text)}
    tenants = {m.group(1).rstrip(",") for m in _TENANT_BIND.finditer(text)}
    shared = admins & tenants
    if not shared:
        return []
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if any(val in line for val in shared) and (
            _ADMIN_BIND.search(line) or _TENANT_BIND.search(line)
        ):
            out.append(
                _finding(
                    "plane.shared-credentials",
                    "Admin and tenant/user credentials share one secret",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                    severity="medium",
                )
            )
    return out


def predictable_tmp(text: str, path: str = "") -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if _TMP_FIXED.search(line) and "mkstemp" not in line and "NamedTemporaryFile" not in line:
            out.append(
                _finding(
                    "fs.predictable-tmp",
                    "Fixed path under /tmp",
                    line=i,
                    evidence=line,
                    confidence="heuristic",
                    path=path,
                    severity="medium",
                )
            )
    return out


def lingering_listen(files: dict[str, str]) -> list[Finding]:
    installs: list[tuple[str, int, str]] = []
    removes = False
    for path, text in files.items():
        name = path.lower()
        if name.endswith(".install") or "post_remove" in name or "pre_remove" in name:
            if re.search(r"systemctl|systemd|\.socket|ListenStream", text, re.I):
                removes = True
        for i, line in enumerate(text.splitlines(), 1):
            if _SYSTEMD_SOCKET.search(line) and (
                ".socket" in line or "ListenStream" in line or "systemd/system" in line
            ):
                installs.append((path, i, line))
    if removes:
        return []
    return [
        _finding(
            "persist.lingering-listen",
            "Listen socket is installed with no matching remove",
            line=line,
            evidence=evidence,
            confidence="config",
            path=path,
        )
        for path, line, evidence in installs
    ]


