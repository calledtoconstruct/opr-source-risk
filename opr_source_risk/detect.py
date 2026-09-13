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
