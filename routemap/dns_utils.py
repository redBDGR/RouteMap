"""Hostname resolution, cached reverse DNS, and private-address classification."""

from __future__ import annotations

import ipaddress
import socket
import threading

_reverse_cache: dict[str, str] = {}
_reverse_cache_lock = threading.Lock()

# RFC1918 + link-local + loopback: deliberately narrower than Python's
# ipaddress.is_private, which also classifies IANA special-use/documentation
# ranges (e.g. 203.0.113.0/24) as "private" — not what we mean by "internal
# to the client's network".
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8")
]


def resolve(target: str) -> tuple[str, str]:
    """Resolve target to (ip, hostname). hostname is "" if target was already an IP."""
    try:
        ipaddress.ip_address(target)
        return target, ""
    except ValueError:
        pass
    ip = socket.gethostbyname(target)
    return ip, target


def reverse_lookup(ip: str) -> str:
    """Return the PTR hostname for ip, or "" if none was found.

    Cached process-wide since the same hop IP is commonly seen across
    traces to many different targets.
    """
    with _reverse_cache_lock:
        if ip in _reverse_cache:
            return _reverse_cache[ip]

    name = ""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        name = ""

    with _reverse_cache_lock:
        _reverse_cache[ip] = name
    return name


def is_private(ip: str) -> bool:
    """True for RFC1918/link-local/loopback addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)
