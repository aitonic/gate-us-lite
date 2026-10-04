from __future__ import annotations

import re
from .models import OpenVPNProfile

PEM_TAGS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")
SAFE_CIPHERS = {"AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC", "CHACHA20-POLY1305"}
SAFE_AUTHS = {"MD5", "SHA1", "SHA256", "SHA384", "SHA512"}
UNSAFE_DIRECTIVES = {
    "script-security", "up", "down", "route-up", "ipchange", "learn-address",
    "client-connect", "client-disconnect", "plugin", "management", "auth-user-pass-verify",
}


def _block(text: str, name: str) -> str:
    m = re.search(rf"<{name}>(.*?)</{name}>", text, re.I | re.S)
    if not m:
        return ""
    return "\n".join(line.strip() for line in m.group(1).replace("\r", "").split("\n") if line.strip())


def _positive_int(value: str | None) -> int:
    try:
        n = int(value or 0)
        return n if n > 0 else 0
    except (TypeError, ValueError):
        return 0


def parse_ovpn(text: str, *, fallback_server: str = "", username: str = "", password: str = "") -> OpenVPNProfile:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        directive = line.split(None, 1)[0].lower()
        if directive in UNSAFE_DIRECTIVES:
            raise ValueError(f"unsafe OpenVPN directive: {directive}")

    remotes = re.findall(r"^[ \t]*remote[ \t]+(\S+)[ \t]+(\d+)(?:[ \t]+(\S+))?[ \t]*\r?$", text, re.I | re.M)
    proto_m = re.search(r"^\s*proto\s+(\S+)", text, re.I | re.M)
    if remotes:
        server, port_s, remote_proto = remotes[0]
    else:
        server, port_s, remote_proto = fallback_server, "1194", ""
    server = fallback_server or server
    proto = (remote_proto or (proto_m.group(1) if proto_m else "udp")).lower()
    proto = "tcp" if "tcp" in proto else "udp"

    ca, cert, key, tls_auth, tls_crypt, tls_crypt_v2 = (_block(text, n) for n in PEM_TAGS)
    if not server:
        raise ValueError("missing remote server")
    if not ca:
        raise ValueError("missing embedded CA certificate")

    cipher_m = re.search(r"^\s*cipher\s+(\S+)", text, re.I | re.M)
    auth_m = re.search(r"^\s*auth\s+(\S+)", text, re.I | re.M)
    dc_m = re.search(r"^\s*data-ciphers\s+(.+)$", text, re.I | re.M)
    comp_m = re.search(r"^\s*comp-lzo(?:\s+(\S+))?", text, re.I | re.M)
    kd_m = re.search(r"^\s*key-direction\s+([01])", text, re.I | re.M)
    ping_m = re.search(r"^\s*ping\s+(\d+)\s*$", text, re.I | re.M)
    ping_restart_m = re.search(r"^\s*ping-restart\s+(\d+)\s*$", text, re.I | re.M)
    keepalive_m = re.search(r"^\s*keepalive\s+(\d+)\s+(\d+)\s*$", text, re.I | re.M)

    cipher = cipher_m.group(1).upper() if cipher_m else ""
    auth = auth_m.group(1).upper() if auth_m else ""
    data_ciphers: list[str] = []
    if dc_m:
        data_ciphers = [x.strip().upper() for x in dc_m.group(1).split(":") if x.strip().upper() in SAFE_CIPHERS]
    comp = (comp_m.group(1) or "yes").lower() if comp_m else ""

    ping = _positive_int(ping_m.group(1) if ping_m else None)
    ping_restart = _positive_int(ping_restart_m.group(1) if ping_restart_m else None)
    if keepalive_m:
        if not ping:
            ping = _positive_int(keepalive_m.group(1))
        if not ping_restart:
            ping_restart = _positive_int(keepalive_m.group(2))

    use_cert = bool(cert and key)
    return OpenVPNProfile(
        server=server,
        port=int(port_s),
        proto=proto,
        ca=ca,
        cert=cert if use_cert else "",
        key=key if use_cert else "",
        username="" if use_cert else username,
        password="" if use_cert else password,
        cipher=cipher if cipher in SAFE_CIPHERS else "",
        auth=auth if auth in SAFE_AUTHS else "",
        data_ciphers=data_ciphers,
        comp_lzo=comp if comp in {"yes", "no", "adaptive"} else "",
        tls_auth=tls_auth,
        key_direction=kd_m.group(1) if kd_m else "",
        tls_crypt=tls_crypt,
        tls_crypt_v2=tls_crypt_v2,
        ping=ping,
        ping_restart=ping_restart,
    )
