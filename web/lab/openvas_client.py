"""Clean GMP (Greenbone Management Protocol) client and OpenVAS XML report parser.

Connects to `gvmd` over a Unix domain socket or TLS TCP socket without
external dependencies, and normalizes OpenVAS XML report results into
Request-Rider `ScannerRun` finding dictionaries.
"""

from __future__ import annotations

import os
import re
import socket
import ssl
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

DEFAULT_GVM_SOCKET = "/run/gvmd/gvmd.sock"
DEFAULT_GVM_HOST = "127.0.0.1"
DEFAULT_GVM_PORT = 9390
DEFAULT_GVM_WEB_URL = "https://127.0.0.1:9392"
GVM_XML_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
DEFAULT_SCAN_CONFIG_NAME = "Full and fast"
DEFAULT_SCANNER_NAME = "OpenVAS Default"

ALIVE_TESTS_OPTIONS = [
    "Scan Config Default",
    "ICMP Ping",
    "TCP-ACK Service Ping",
    "TCP-SYN Service Ping",
    "ARP Ping",
    "ICMP & TCP-ACK Service Ping",
    "ICMP & ARP Ping",
    "TCP-ACK Service & ARP Ping",
    "ICMP, TCP-ACK Service & ARP Ping",
    "Consider Alive",
]

HOSTS_ORDERING_OPTIONS = ["sequential", "random", "reverse"]

_UNSAFE_XML_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_DEFAULT_GVM_ENV_FILE = Path(__file__).resolve().parents[2] / "data" / "gvm.env"


def _gvm_credentials_path() -> Path | None:
    custom = os.environ.get("GVM_CREDENTIALS_FILE", "").strip()
    if custom == "none":
        return None
    if custom:
        return Path(custom)
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        return None
    return _DEFAULT_GVM_ENV_FILE


def load_saved_gvm_credentials() -> tuple[str, str]:
    """Read GVM_USER and GVM_PASSWORD from local 0600 gvm.env if present."""
    path = _gvm_credentials_path()
    if path is None or not path.is_file():
        return "", ""
    user = ""
    password = ""
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if key.startswith("export "):
                key = key[7:].strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            if key == "GVM_USER":
                user = val
            elif key == "GVM_PASSWORD":
                password = val
    except OSError:
        return "", ""
    return user, password


def save_gvm_credentials(username: str, password: str) -> None:
    """Persist GVM credentials to local 0600 gvm.env and current process env."""
    clean_user = (username or "admin").strip() or "admin"
    clean_pwd = (password or "").strip()
    if not clean_pwd:
        return
    os.environ["GVM_USER"] = clean_user
    os.environ["GVM_PASSWORD"] = clean_pwd
    path = _gvm_credentials_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        escaped_user = clean_user.replace("\\", "\\\\").replace('"', '\\"')
        escaped_pwd = clean_pwd.replace("\\", "\\\\").replace('"', '\\"')
        content = f'GVM_USER="{escaped_user}"\nGVM_PASSWORD="{escaped_pwd}"\n'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(str(path), 0o600)
    except OSError:
        pass


class GVMError(RuntimeError):
    """Raised when GMP communication or response validation fails."""


def is_auth_required_error(exc: Exception) -> bool:
    """Return True when gvmd rejected a command because AUTHENTICATE was not completed or failed."""
    msg = str(exc).lower()
    return (
        "only command get_version is allowed before authenticate" in msg
        or "gmp authenticate failed" in msg
        or "authentication failed" in msg
    )


def safe_fromstring(xml_text: str) -> ET.Element:
    """Parse XML text safely by rejecting DOCTYPE/ENTITY declarations (XXE guard)."""
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise GVMError("Empty XML payload")
    if _UNSAFE_XML_RE.search(xml_text):
        raise GVMError("Unsafe XML declaration (DOCTYPE/ENTITY) rejected")
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise GVMError(f"Invalid XML from gvmd: {exc}") from exc


def _normalize_target_host(target: str) -> str:
    """Extract hostname or IP from a URL or bare host string."""
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw
    return raw.split("/")[0].split(":")[0].strip()


def _normalize_target_hosts_list(hosts: str) -> str:
    """Normalize comma/whitespace-separated host/CIDR/URL entries for GMP create_target."""
    parts = [p.strip() for p in re.split(r"[\n,;]+", hosts or "") if p.strip()]
    normalized: list[str] = []
    for part in parts:
        if "://" in part:
            host = _normalize_target_host(part)
            if host:
                normalized.append(host)
        else:
            normalized.append(part)
    return ", ".join(normalized)


ACTIVE_GVM_TASK_STATUSES = frozenset({"running", "requested", "queued", "stop requested"})


def find_matching_task(
    tasks: list[dict[str, Any]],
    task_name: str,
    target_url: str,
) -> tuple[dict[str, Any] | None, bool]:
    """Find an existing matching task (preferring active tasks over idle same-name tasks).

    Returns (task_dict, is_active).
    """
    norm_target = _normalize_target_hosts_list(target_url) or (target_url or "").strip()
    clean_name = (task_name or "").strip()

    for task in tasks or []:
        st = str(task.get("status") or "").strip().lower()
        if st not in ACTIVE_GVM_TASK_STATUSES:
            continue
        t_name = str(task.get("name") or "").strip()
        t_target = _normalize_target_hosts_list(str(task.get("target") or "")) or str(task.get("target") or "").strip()
        if (clean_name and t_name == clean_name) or (norm_target and t_target == norm_target):
            return task, True

    if clean_name:
        for task in tasks or []:
            if str(task.get("name") or "").strip() == clean_name:
                return task, False

    return None, False


def _severity_from_threat_and_cvss(threat: str, cvss_val: float | None) -> str:
    """Map OpenVAS threat level / CVSS score to Request-Rider severity."""
    t = (threat or "").strip().lower()
    if cvss_val is not None:
        if cvss_val >= 9.0:
            return "critical"
        if cvss_val >= 7.0:
            return "high"
        if cvss_val >= 4.0:
            return "medium"
        if cvss_val > 0.0:
            return "low"
        return "info"
    if t in ("critical",):
        return "critical"
    if t in ("high",):
        return "high"
    if t in ("medium",):
        return "medium"
    if t in ("low",):
        return "low"
    if t in ("log", "info", "none", "false positive"):
        return "info"
    return "unknown"


@dataclass
class GVMConnectionConfig:
    """Connection parameters for gvmd GMP endpoint."""

    socket_path: str = ""
    host: str = ""
    port: int = DEFAULT_GVM_PORT
    username: str = ""
    password: str = ""
    timeout: float = 30.0
    tls_verify: bool = False

    @classmethod
    def from_env_and_payload(cls, payload: dict[str, Any] | None = None) -> "GVMConnectionConfig":
        data = payload or {}
        socket_path = str(
            data.get("socket_path")
            or os.environ.get("GVM_SOCKET")
            or DEFAULT_GVM_SOCKET
        ).strip()
        host = str(data.get("host") or os.environ.get("GVM_HOST") or "").strip()
        port_raw = data.get("port") or os.environ.get("GVM_PORT") or DEFAULT_GVM_PORT
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            port = DEFAULT_GVM_PORT
        saved_user, saved_pwd = load_saved_gvm_credentials()
        # Credential priority:
        # 1. Explicit payload from current user/request
        # 2. Saved credentials in local 0600 data/gvm.env
        # 3. Environment variables GVM_USER / GVM_PASSWORD
        # 4. Fallback defaults
        username = str(data.get("username") or saved_user or os.environ.get("GVM_USER") or "admin").strip()
        password = str(data.get("password") or saved_pwd or os.environ.get("GVM_PASSWORD") or "").strip()
        timeout_raw = data.get("timeout") or 30.0
        try:
            timeout = max(5.0, float(timeout_raw))
        except (TypeError, ValueError):
            timeout = 30.0
        tls_verify = bool(data.get("tls_verify", False))
        return cls(
            socket_path=socket_path,
            host=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            tls_verify=tls_verify,
        )


class GMPClient:
    """Minimal synchronous GMP (Greenbone Management Protocol) XML client."""

    def __init__(self, config: GVMConnectionConfig) -> None:
        self.config = config
        self._sock: socket.socket | ssl.SSLSocket | None = None

    def __enter__(self) -> "GMPClient":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def connect(self) -> None:
        if self._sock is not None:
            return
        if self.config.host:
            try:
                raw_sock = socket.create_connection(
                    (self.config.host, self.config.port),
                    timeout=self.config.timeout,
                )
                ctx = ssl.create_default_context()
                if not self.config.tls_verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                self._sock = ctx.wrap_socket(raw_sock, server_hostname=self.config.host)
            except OSError as exc:
                raise GVMError(
                    f"failed to connect to GVM at {self.config.host}:{self.config.port}: {exc}"
                ) from exc
        else:
            sock_path = self.config.socket_path or DEFAULT_GVM_SOCKET
            if not os.path.exists(sock_path):
                raise GVMError(f"gvmd socket not found at {sock_path}")
            unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_sock.settimeout(self.config.timeout)
            try:
                unix_sock.connect(sock_path)
            except PermissionError as exc:
                unix_sock.close()
                raise GVMError(
                    f"permission denied connecting to gvmd socket {sock_path}: {exc}. "
                    "Add the current user to the _gvm group or configure GVM_HOST/GVM_PORT."
                ) from exc
            except OSError as exc:
                unix_sock.close()
                raise GVMError(
                    f"failed to connect to gvmd socket {sock_path}: {exc}"
                ) from exc
            self._sock = unix_sock

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def send_xml(self, command_xml: str) -> ET.Element:
        """Send a single GMP XML command and return the parsed response root."""
        if self._sock is None:
            self.connect()
        assert self._sock is not None
        payload = command_xml.encode("utf-8")
        self._sock.sendall(payload)

        chunks: list[bytes] = []
        while True:
            data = self._sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            joined = b"".join(chunks).decode("utf-8", errors="replace")
            try:
                root = safe_fromstring(joined)
                return root
            except GVMError as exc:
                if "Invalid XML" in str(exc):
                    # Incomplete XML frame; keep reading until tag closes.
                    continue
                raise

        full_text = b"".join(chunks).decode("utf-8", errors="replace")
        if not full_text.strip():
            raise GVMError("Connection closed by gvmd without response")
        return safe_fromstring(full_text)

    @staticmethod
    def _assert_ok(root: ET.Element, context: str) -> ET.Element:
        status = root.attrib.get("status", "")
        if not status.startswith("2"):
            status_text = root.attrib.get("status_text", "Unknown error")
            raise GVMError(f"GMP {context} failed ({status}): {status_text}")
        return root

    def authenticate(self, username: str | None = None, password: str | None = None) -> None:
        user = username if username is not None else self.config.username
        pwd = password if password is not None else self.config.password
        resp = self.send_xml(
            f"<authenticate><credentials><username>{xml_escape(user)}</username>"
            f"<password>{xml_escape(pwd)}</password></credentials></authenticate>"
        )
        try:
            self._assert_ok(resp, "authenticate")
        except GVMError as exc:
            # If authenticate failed on current credentials, try fallback to saved gvm.env file
            if username is None and password is None:
                saved_user, saved_pwd = load_saved_gvm_credentials()
                if saved_pwd and saved_pwd != pwd:
                    fallback_user = saved_user or user
                    try:
                        self.close()
                    except Exception:
                        pass
                    self.connect()
                    fallback_resp = self.send_xml(
                        f"<authenticate><credentials><username>{xml_escape(fallback_user)}</username>"
                        f"<password>{xml_escape(saved_pwd)}</password></credentials></authenticate>"
                    )
                    self._assert_ok(fallback_resp, "authenticate")
                    self.config.username = fallback_user
                    self.config.password = saved_pwd
                    save_gvm_credentials(fallback_user, saved_pwd)
                    return
            raise exc

    def get_version(self) -> str:
        resp = self._assert_ok(self.send_xml("<get_version/>"), "get_version")
        return (resp.findtext("version") or "").strip()

    def _list_gmp_items(self, command: str, item_tag: str, extra_fields: tuple[str, ...] = ("comment",)) -> list[dict[str, str]]:
        resp = self._assert_ok(self.send_xml(command), command.strip("</>"))
        items: list[dict[str, str]] = []
        for el in resp.findall(f".//{item_tag}"):
            item_id = (el.attrib.get("id") or "").strip()
            if not item_id:
                continue
            entry: dict[str, str] = {
                "id": item_id,
                "name": (el.findtext("name") or item_id).strip(),
            }
            for field in extra_fields:
                val = (el.findtext(field) or "").strip()
                if val:
                    entry[field] = val
            items.append(entry)
        return items

    def get_configs(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_configs/>", "config")

    def get_scanners(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_scanners/>", "scanner", extra_fields=("type", "comment"))

    def get_port_lists(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_port_lists/>", "port_list")

    def get_credentials(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_credentials/>", "credential", extra_fields=("type", "comment"))

    def get_schedules(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_schedules/>", "schedule")

    def get_alerts(self) -> list[dict[str, str]]:
        return self._list_gmp_items("<get_alerts/>", "alert")

    def get_options(self) -> dict[str, Any]:
        """Return all GVM Target/Task configuration options for UI parity with GSA."""
        return {
            "configs": self.get_configs(),
            "scanners": self.get_scanners(),
            "port_lists": self.get_port_lists(),
            "credentials": self.get_credentials(),
            "schedules": self.get_schedules(),
            "alerts": self.get_alerts(),
            "alive_tests": list(ALIVE_TESTS_OPTIONS),
            "hosts_ordering": list(HOSTS_ORDERING_OPTIONS),
        }

    def find_config_id(self, name: str = DEFAULT_SCAN_CONFIG_NAME) -> str:
        configs = self.get_configs()
        for cfg in configs:
            if cfg["name"].lower() == name.lower():
                return cfg["id"]
        if configs:
            return configs[0]["id"]
        raise GVMError("No scan configs available in gvmd (feed sync may still be in progress)")

    def find_scanner_id(self, name: str = DEFAULT_SCANNER_NAME) -> str:
        scanners = self.get_scanners()
        for sc in scanners:
            if sc["name"].lower() == name.lower():
                return sc["id"]
        if scanners:
            return scanners[0]["id"]
        raise GVMError("No scanners available in gvmd")

    def find_port_list_id(self, name: str = "All TCP and Nmap top 100 UDP") -> str:
        port_lists = self.get_port_lists()
        for pl in port_lists:
            if pl["name"].lower() == name.lower():
                return pl["id"]
        if port_lists:
            return port_lists[0]["id"]
        raise GVMError("No port lists available in gvmd")

    def create_target(
        self,
        name: str,
        hosts: str,
        *,
        exclude_hosts: str = "",
        port_list_id: str = "",
        alive_tests: str = "",
        reverse_lookup_only: bool = False,
        reverse_lookup_unify: bool = False,
        ssh_credential_id: str = "",
        ssh_port: int | None = None,
        smb_credential_id: str = "",
        esxi_credential_id: str = "",
        snmp_credential_id: str = "",
        comment: str = "",
    ) -> str:
        clean_hosts = _normalize_target_hosts_list(hosts) or hosts.strip()
        cmd = ET.Element("create_target")
        ET.SubElement(cmd, "name").text = name
        ET.SubElement(cmd, "hosts").text = clean_hosts
        if exclude_hosts and exclude_hosts.strip():
            ET.SubElement(cmd, "exclude_hosts").text = _normalize_target_hosts_list(exclude_hosts) or exclude_hosts.strip()
        resolved_port_list_id = (port_list_id or "").strip() or self.find_port_list_id()
        ET.SubElement(cmd, "port_list", {"id": resolved_port_list_id})
        resolved_alive = (alive_tests or "").strip() or "Consider Alive"
        ET.SubElement(cmd, "alive_tests").text = resolved_alive
        if reverse_lookup_only:
            ET.SubElement(cmd, "reverse_lookup_only").text = "1"
        if reverse_lookup_unify:
            ET.SubElement(cmd, "reverse_lookup_unify").text = "1"
        if ssh_credential_id and ssh_credential_id.strip():
            cred_el = ET.SubElement(cmd, "ssh_credential", {"id": ssh_credential_id.strip()})
            if ssh_port:
                ET.SubElement(cred_el, "port").text = str(int(ssh_port))
        if smb_credential_id and smb_credential_id.strip():
            ET.SubElement(cmd, "smb_credential", {"id": smb_credential_id.strip()})
        if esxi_credential_id and esxi_credential_id.strip():
            ET.SubElement(cmd, "esxi_credential", {"id": esxi_credential_id.strip()})
        if snmp_credential_id and snmp_credential_id.strip():
            ET.SubElement(cmd, "snmp_credential", {"id": snmp_credential_id.strip()})
        if comment and comment.strip():
            ET.SubElement(cmd, "comment").text = comment.strip()

        resp = self._assert_ok(self.send_xml(ET.tostring(cmd, encoding="unicode")), "create_target")
        target_id = resp.attrib.get("id", "")
        if not target_id:
            raise GVMError("gvmd did not return target id")
        return target_id

    def create_task(
        self,
        name: str,
        config_id: str,
        target_id: str,
        scanner_id: str,
        *,
        comment: str = "",
        hosts_ordering: str = "",
        max_checks: int | None = None,
        max_hosts: int | None = None,
        source_iface: str = "",
        schedule_id: str = "",
        alert_id: str = "",
        in_assets: bool | None = None,
        apply_overrides: bool | None = None,
        min_qod: int | None = None,
        alterable: bool | None = None,
        auto_delete: str = "",
        auto_delete_data: int | None = None,
    ) -> str:
        cmd = ET.Element("create_task")
        ET.SubElement(cmd, "name").text = name
        if comment and comment.strip():
            ET.SubElement(cmd, "comment").text = comment.strip()
        ET.SubElement(cmd, "config", {"id": config_id})
        ET.SubElement(cmd, "target", {"id": target_id})
        ET.SubElement(cmd, "scanner", {"id": scanner_id})
        if hosts_ordering and hosts_ordering.strip() in HOSTS_ORDERING_OPTIONS:
            ET.SubElement(cmd, "hosts_ordering").text = hosts_ordering.strip()
        if schedule_id and schedule_id.strip():
            ET.SubElement(cmd, "schedule", {"id": schedule_id.strip()})
        if alert_id and alert_id.strip():
            ET.SubElement(cmd, "alert", {"id": alert_id.strip()})
        if alterable is not None:
            ET.SubElement(cmd, "alterable").text = "1" if alterable else "0"

        prefs_items: list[tuple[str, str]] = []
        if max_checks is not None and int(max_checks) > 0:
            prefs_items.append(("max_checks", str(int(max_checks))))
        if max_hosts is not None and int(max_hosts) > 0:
            prefs_items.append(("max_hosts", str(int(max_hosts))))
        if source_iface and source_iface.strip():
            prefs_items.append(("network_scan_iface", source_iface.strip()))
        if in_assets is not None:
            prefs_items.append(("in_assets", "yes" if in_assets else "no"))
        if apply_overrides is not None:
            prefs_items.append(("apply_overrides", "yes" if apply_overrides else "no"))
        if min_qod is not None:
            prefs_items.append(("min_qod", str(max(0, min(100, int(min_qod))))))
        if auto_delete in ("keep", "no"):
            prefs_items.append(("auto_delete", auto_delete))
            if auto_delete == "keep" and auto_delete_data is not None and int(auto_delete_data) > 0:
                prefs_items.append(("auto_delete_data", str(int(auto_delete_data))))
        if prefs_items:
            prefs_el = ET.SubElement(cmd, "preferences")
            for pname, pval in prefs_items:
                pref = ET.SubElement(prefs_el, "preference")
                ET.SubElement(pref, "scanner_name").text = pname
                ET.SubElement(pref, "value").text = pval

        resp = self._assert_ok(self.send_xml(ET.tostring(cmd, encoding="unicode")), "create_task")
        task_id = resp.attrib.get("id", "")
        if not task_id:
            raise GVMError("gvmd did not return task id")
        return task_id

    def start_task(self, task_id: str) -> str:
        resp = self._assert_ok(
            self.send_xml(f'<start_task task_id="{xml_escape(task_id)}"/>'),
            "start_task",
        )
        return (resp.findtext("report_id") or "").strip()

    def stop_task(self, task_id: str) -> None:
        self._assert_ok(
            self.send_xml(f'<stop_task task_id="{xml_escape(task_id)}"/>'),
            "stop_task",
        )

    def resume_task(self, task_id: str) -> str:
        resp = self._assert_ok(
            self.send_xml(f'<resume_task task_id="{xml_escape(task_id)}"/>'),
            "resume_task",
        )
        return (resp.findtext("report_id") or "").strip()

    def delete_task(self, task_id: str) -> None:
        self._assert_ok(
            self.send_xml(f'<delete_task task_id="{xml_escape(task_id)}" ultimate="0"/>'),
            "delete_task",
        )

    def create_port_list(self, name: str, port_range: str, comment: str = "") -> str:
        cmd = ET.Element("create_port_list")
        ET.SubElement(cmd, "name").text = name.strip()
        ET.SubElement(cmd, "port_range").text = port_range.strip()
        if comment and comment.strip():
            ET.SubElement(cmd, "comment").text = comment.strip()
        resp = self._assert_ok(self.send_xml(ET.tostring(cmd, encoding="unicode")), "create_port_list")
        pl_id = resp.attrib.get("id", "")
        if not pl_id:
            raise GVMError("gvmd did not return port_list id")
        return pl_id

    def create_credential(
        self,
        name: str,
        username: str = "",
        password: str = "",
        credential_type: str = "up",
        comment: str = "",
        private_key: str = "",
        passphrase: str = "",
        auth_algorithm: str = "",
        privacy_password: str = "",
        privacy_algorithm: str = "",
    ) -> str:
        ctype = (credential_type or "up").strip().lower()
        cmd = ET.Element("create_credential")
        ET.SubElement(cmd, "name").text = name.strip()
        ET.SubElement(cmd, "type").text = ctype
        if username and username.strip():
            ET.SubElement(cmd, "login").text = username.strip()
        if ctype == "usk":
            key_el = ET.SubElement(cmd, "key")
            ET.SubElement(key_el, "private").text = private_key
            if passphrase:
                ET.SubElement(key_el, "phrase").text = passphrase
        else:
            if password:
                ET.SubElement(cmd, "password").text = password
        if ctype == "snmp":
            if auth_algorithm and auth_algorithm.strip():
                ET.SubElement(cmd, "auth_algorithm").text = auth_algorithm.strip().lower()
            if privacy_password or (privacy_algorithm and privacy_algorithm.strip()):
                priv_el = ET.SubElement(cmd, "privacy")
                if privacy_password:
                    ET.SubElement(priv_el, "password").text = privacy_password
                if privacy_algorithm and privacy_algorithm.strip():
                    ET.SubElement(priv_el, "algorithm").text = privacy_algorithm.strip().lower()
        if comment and comment.strip():
            ET.SubElement(cmd, "comment").text = comment.strip()
        resp = self._assert_ok(self.send_xml(ET.tostring(cmd, encoding="unicode")), "create_credential")
        cred_id = resp.attrib.get("id", "")
        if not cred_id:
            raise GVMError("gvmd did not return credential id")
        return cred_id

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        resp = self._assert_ok(
            self.send_xml(f'<get_tasks task_id="{xml_escape(task_id)}"/>'),
            "get_tasks",
        )
        task = resp.find(".//task")
        if task is None:
            raise GVMError(f"Task {task_id} not found")
        status = (task.findtext("status") or "").strip()
        progress_text = (task.findtext("progress") or "0").strip()
        try:
            progress = int(progress_text)
        except ValueError:
            progress = 0
        report_el = task.find(".//last_report/report") or task.find(".//current_report/report")
        report_id = report_el.attrib.get("id", "") if report_el is not None else ""
        return {
            "task_id": task_id,
            "status": status,
            "progress": progress,
            "report_id": report_id,
        }

    def get_targets(self) -> list[dict[str, str]]:
        """List existing targets in gvmd."""
        resp = self._assert_ok(self.send_xml('<get_targets filter="rows=-1"/>'), "get_targets")
        targets: list[dict[str, str]] = []
        for tgt in resp.findall(".//target"):
            tid = tgt.attrib.get("id", "")
            if not tid:
                continue
            targets.append({
                "id": tid,
                "name": (tgt.findtext("name") or "").strip(),
                "hosts": (tgt.findtext("hosts") or "").strip(),
            })
        return targets

    def get_tasks(self) -> list[dict[str, Any]]:
        """List existing tasks in gvmd including their latest report metadata."""
        resp = self._assert_ok(
            self.send_xml('<get_tasks filter="rows=-1 sort-reverse=modification_time"/>'),
            "get_tasks",
        )
        tasks: list[dict[str, Any]] = []
        for task in resp.findall(".//task"):
            task_id = task.attrib.get("id", "")
            if not task_id:
                continue
            status = (task.findtext("status") or "").strip()
            progress_text = (task.findtext("progress") or "0").strip()
            try:
                progress = int(progress_text)
            except ValueError:
                progress = 0
            report_el = task.find(".//last_report/report") or task.find(".//current_report/report")
            report_id = report_el.attrib.get("id", "") if report_el is not None else ""
            timestamp = (report_el.findtext("timestamp") or task.findtext("modification_time") or "").strip() if report_el is not None else (task.findtext("modification_time") or "").strip()
            target_el = task.find("target")
            target_id = target_el.attrib.get("id", "") if target_el is not None else ""
            target_name = ""
            if target_el is not None:
                raw_target = (target_el.findtext("hosts") or target_el.findtext("name") or "").strip()
                if raw_target.startswith("RR-") and len(raw_target) > 3:
                    target_name = raw_target[3:]
                else:
                    target_name = raw_target
            tasks.append({
                "task_id": task_id,
                "name": (task.findtext("name") or task_id).strip(),
                "status": status,
                "progress": progress,
                "report_id": report_id,
                "target_id": target_id,
                "target": target_name,
                "timestamp": timestamp,
            })
        return tasks

    def get_report_xml(self, report_id: str) -> str:
        resp = self._assert_ok(
            self.send_xml(
                f'<get_reports report_id="{xml_escape(report_id)}" '
                f'format_id="{GVM_XML_REPORT_FORMAT_ID}" details="1"/>'
            ),
            "get_reports",
        )
        return ET.tostring(resp, encoding="unicode")


def parse_openvas_report_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse an OpenVAS/GVM XML report into normalized ScannerRun finding dicts."""
    root = safe_fromstring(xml_text)
    findings: list[dict[str, Any]] = []
    for res in root.findall(".//results/result"):
        nvt = res.find("nvt")
        oid = nvt.attrib.get("oid", "") if nvt is not None else ""
        title = (
            (res.findtext("name") or "").strip()
            or (nvt.findtext("name") if nvt is not None else "")
            or "OpenVAS Finding"
        ).strip()
        host = (res.findtext("host") or "").strip()
        port = (res.findtext("port") or "").strip()
        threat = (res.findtext("threat") or "").strip()
        severity_raw = (res.findtext("severity") or "").strip()
        cvss_val: float | None = None
        if severity_raw:
            try:
                cvss_val = float(severity_raw)
            except ValueError:
                cvss_val = None
        if cvss_val is None and nvt is not None:
            cvss_base = (nvt.findtext("cvss_base") or "").strip()
            if cvss_base:
                try:
                    cvss_val = float(cvss_base)
                except ValueError:
                    cvss_val = None

        severity = _severity_from_threat_and_cvss(threat, cvss_val)
        qod_val: int | None = None
        qod_raw = (res.findtext("qod/value") or "").strip()
        if qod_raw:
            try:
                qod_val = int(float(qod_raw))
            except ValueError:
                qod_val = None

        nvt_tags: dict[str, str] = {}
        if nvt is not None:
            tags_raw = (nvt.findtext("tags") or "").strip()
            if tags_raw:
                for part in tags_raw.split("|"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        nvt_tags[k.strip().lower()] = v.strip()

        description = (res.findtext("description") or "").strip()
        if not description and nvt_tags.get("summary"):
            description = nvt_tags["summary"]
        impact = (res.findtext("impact") or nvt_tags.get("impact") or "").strip()
        evidence = (
            res.findtext("evidence")
            or res.findtext("detection/result/details/detail/value")
            or ""
        ).strip()

        solution = ""
        cves: list[str] = []
        if nvt is not None:
            solution = (nvt.findtext("solution") or "").strip()
            for ref in nvt.findall(".//refs/ref"):
                if (ref.attrib.get("type") or "").lower() == "cve":
                    ref_id = (ref.attrib.get("id") or "").strip()
                    if ref_id:
                        cves.append(ref_id)
            cve_text = (nvt.findtext("cve") or "").strip()
            if cve_text and cve_text.upper() != "NOCVE":
                for item in cve_text.split(","):
                    cleaned = item.strip()
                    if cleaned and cleaned not in cves:
                        cves.append(cleaned)

        endpoint = f"{host}:{port}" if host and port else (host or port)
        findings.append(
            {
                "title": title,
                "name": title,
                "severity": severity,
                "cvss": cvss_val,
                "qod": qod_val,
                "host": host,
                "port": port,
                "endpoint": endpoint,
                "nvt_oid": oid,
                "template_id": oid or title,
                "cve": cves,
                "description": description,
                "impact": impact,
                "evidence": evidence,
                "solution": solution,
                "threat": threat,
                "engine": "openvas",
            }
        )
    enrich_openvas_cve_findings(findings)
    return findings


_CVE_ENRICH_CACHE: dict[str, dict[str, Any]] = {}
_KEV_FEED_CACHE: dict[str, dict[str, str]] | None = None


def enrich_openvas_cve_findings(
    findings: list[dict[str, Any]],
    *,
    timeout_s: float = 1.5,
    epss_url: str = "https://api.first.org/data/v1/epss",
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
) -> None:
    """Enrich OpenVAS findings containing CVEs with EPSS & CISA KEV metadata (best-effort, cached)."""
    global _KEV_FEED_CACHE
    import json as _json
    import urllib.parse as _urlparse
    import urllib.request as _urlreq

    if not findings:
        return
    need_cves = {
        str(c).strip().upper()
        for f in findings
        for c in (f.get("cve") or [])
        if str(c).strip().upper().startswith("CVE-")
    }
    if not need_cves:
        return

    if _KEV_FEED_CACHE is None and kev_url:
        try:
            with _urlreq.urlopen(kev_url, timeout=timeout_s) as resp:
                kev_data = _json.loads(resp.read().decode("utf-8"))
            _KEV_FEED_CACHE = {
                str(v.get("cveID", "")).strip().upper(): {
                    "known_ransomware_campaign_use": str(v.get("knownRansomwareCampaignUse") or ""),
                }
                for v in (kev_data.get("vulnerabilities") or [])
                if v.get("cveID")
            }
        except Exception:
            _KEV_FEED_CACHE = {}

    for cve_id in need_cves:
        if cve_id in _CVE_ENRICH_CACHE:
            continue
        meta: dict[str, Any] = {}
        if epss_url:
            try:
                q_url = f"{epss_url.rstrip('?')}?cve={_urlparse.quote(cve_id)}"
                with _urlreq.urlopen(q_url, timeout=timeout_s) as resp:
                    epss_data = _json.loads(resp.read().decode("utf-8"))
                rows = epss_data.get("data") or []
                if rows:
                    meta["epss_score"] = float(rows[0].get("epss") or 0.0)
                    meta["epss_percentile"] = float(rows[0].get("percentile") or 0.0)
            except Exception:
                pass
        if _KEV_FEED_CACHE and cve_id in _KEV_FEED_CACHE:
            meta["is_kev"] = True
            meta["is_exploited"] = True
            ransom = _KEV_FEED_CACHE[cve_id].get("known_ransomware_campaign_use")
            if ransom:
                meta["known_ransomware_campaign_use"] = ransom
        if meta:
            _CVE_ENRICH_CACHE[cve_id] = meta

    poc_keywords = ("github.com", "exploit-db.com", "packetstormsecurity.com", "packetstorm.news", "0day.today", "cxsecurity.com", "seclists.org", "sploitus.com", "edb-id")
    import re as _re
    for f in findings:
        best: dict[str, Any] | None = None
        for raw_cve in f.get("cve") or []:
            meta = _CVE_ENRICH_CACHE.get(str(raw_cve).strip().upper())
            if not meta:
                continue
            if best is None or meta.get("epss_score", 0.0) > best.get("epss_score", 0.0) or (meta.get("is_kev") and not best.get("is_kev")):
                best = meta
        if best:
            f.update(best)

        # Auto-detect public PoC links in references or text fields if not already populated
        auto_pocs: list[dict[str, str]] = []
        seen_urls: set[str] = {p.get("url", "") for p in (f.get("poc") or []) if isinstance(p, dict)}
        all_refs: list[str] = []
        raw_refs = f.get("references") or f.get("reference") or []
        if isinstance(raw_refs, list):
            all_refs.extend(str(r) for r in raw_refs)
        elif isinstance(raw_refs, str):
            all_refs.append(raw_refs)
        for text_val in (f.get("description"), f.get("threat"), f.get("solution"), f.get("evidence")):
            if text_val and any(kw in str(text_val).lower() for kw in poc_keywords):
                for match in _re.findall(r'https?://[^\s<>"\'\)]+', str(text_val)):
                    all_refs.append(match)
        for ref in all_refs:
            ref_clean = ref.strip().rstrip(".,;)")
            if ref_clean and ref_clean not in seen_urls and any(kw in ref_clean.lower() for kw in poc_keywords):
                seen_urls.add(ref_clean)
                auto_pocs.append({"url": ref_clean, "source": "reference"})
        if auto_pocs:
            f["is_poc"] = True
            existing_pocs = list(f.get("poc") or [])
            existing_pocs.extend(auto_pocs)
            f["poc"] = existing_pocs


def _resolve_gvm_web_url(cfg: GVMConnectionConfig, payload: dict[str, Any] | None = None) -> str:
    raw = str((payload or {}).get("web_url") or os.environ.get("GVM_WEB_URL") or "").strip()
    if raw:
        return raw
    if cfg.host:
        return f"https://{cfg.host}:9392"
    return DEFAULT_GVM_WEB_URL


def _probe_gvm_web_ui(web_url: str, timeout_s: float = 0.4) -> bool:
    parsed = urlparse(web_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def check_gvmd_status(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Check whether gvmd is reachable and return version/diagnostic info."""
    cfg = GVMConnectionConfig.from_env_and_payload(payload)
    target_desc = f"{cfg.host}:{cfg.port}" if cfg.host else cfg.socket_path
    web_url = _resolve_gvm_web_url(cfg, payload)
    web_reachable = _probe_gvm_web_ui(web_url)
    try:
        with GMPClient(cfg) as client:
            version = client.get_version()
            authenticated = False
            auth_error = ""
            if cfg.password:
                try:
                    client.authenticate()
                    authenticated = True
                    if payload and payload.get("password"):
                        save_gvm_credentials(cfg.username, cfg.password)
                except GVMError as auth_exc:
                    auth_error = str(auth_exc)
        return {
            "available": True,
            "endpoint": target_desc,
            "gmp_version": version,
            "web_url": web_url,
            "web_reachable": web_reachable,
            "auth_configured": bool(cfg.password),
            "authenticated": authenticated,
            "auth_error": auth_error,
            "active_user": cfg.username if authenticated else "",
        }
    except Exception as exc:
        return {
            "available": False,
            "endpoint": target_desc,
            "error": str(exc),
            "web_url": web_url,
            "web_reachable": web_reachable,
        }
