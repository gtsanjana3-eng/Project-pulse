"""SSRF guard: validate URLs and resolve to globally-routable IPs only."""
import ipaddress, socket
from urllib.parse import urlsplit

ALLOWED_PORTS = {80, 443, 8080, 8443}

class UnsafeURL(ValueError):
    pass

def _default_resolver(host, port):
    return [ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)]

def validate_url(url, resolver=_default_resolver, *, allow=frozenset()):
    """Return (parts, host, port, pinned_ip). Raises UnsafeURL.
    Every resolved address must be public; the caller connects to pinned_ip
    (not the hostname) so DNS rebinding between check and connect is impossible."""
    if not isinstance(url, str) or len(url) > 2048:
        raise UnsafeURL("invalid url")
    p = urlsplit(url.strip())
    if p.scheme not in ("http", "https"):
        raise UnsafeURL("only http/https allowed")
    if p.username or p.password:
        raise UnsafeURL("credentials in url not allowed")
    if not p.hostname:
        raise UnsafeURL("missing host")
    port = p.port or (443 if p.scheme == "https" else 80)
    # `allow`: exact (literal-IP, port) pairs. Used ONLY by tests that serve a fixture on localhost.
    # Never populated from env/requests/config; hostnames are never accepted here.
    if (p.hostname, port) in allow:
        ipaddress.ip_address(p.hostname)
        return p, p.hostname, port, p.hostname
    if port not in ALLOWED_PORTS:
        raise UnsafeURL(f"port {port} not allowed")
    try:
        ips = resolver(p.hostname, port)
    except OSError:
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
