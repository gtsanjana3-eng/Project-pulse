"""SSRF guard: validate URLs and resolve to globally-routable IPs only."""
import ipaddress, socket
from urllib.parse import urlsplit

ALLOWED_PORTS = {80, 443, 8080, 8443}

class UnsafeURL(ValueError):
    pass

def _default_resolver(host, port):
    return [ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)]

def validate_url(url, resolver=_default_resolver, *, allow=frozenset()):
    """Return (parts, host, port, pinned_ip). Raises UnsafeURL."""
    if not isinstance(url, str) or len(url) > 2048:
        raise UnsafeURL("invalid url")

    p = urlsplit(url.strip())

    if p.scheme not in ("http", "https"):
        raise UnsafeURL("only http/https allowed")
    if p.username or p.password:
        raise UnsafeURL("credentials in url not allowed")
    if not p.hostname:
        raise UnsafeURL("missing host")

    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise UnsafeURL("invalid port")

    # Test-only exception: exact literal IP and port match.
    if (p.hostname, port) in allow:
        try:
            ipaddress.ip_address(p.hostname)
        except ValueError:
            raise UnsafeURL("test allowlist requires a literal IP address")
        return p, p.hostname, port, p.hostname

    try:
        literal_ip = ipaddress.ip_address(p.hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None and not literal_ip.is_global:
        raise UnsafeURL("target must be a public IP address")

    if port not in ALLOWED_PORTS:
        raise UnsafeURL(f"port {port} not allowed")

    try:
        ips = resolver(p.hostname, port)
    except (OSError, ValueError):
        raise UnsafeURL("host could not be resolved")

    if not ips:
        raise UnsafeURL("host could not be resolved")

    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise UnsafeURL("target resolves to a non-public address")

    return p, p.hostname, port, ips[0]
