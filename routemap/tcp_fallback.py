"""TCP-connect probing, used as a fallback on hops that ICMP can't reach.

Deliberately avoids crafting raw TCP packets (which Windows has blocked
since XP SP2, and which would otherwise require installing Npcap). Instead
this sets IP_TTL on a normal socket before connect() and listens on a
separate raw ICMP socket for the resulting "Time Exceeded" reply — the same
result with nothing beyond local admin rights.
"""

from __future__ import annotations

import errno
import queue
import socket
import struct
import threading
import time

from .models import Options, Probe
from .packet_utils import split_ip_header

# WSAECONNREFUSED (10061) is Windows' equivalent of errno.ECONNREFUSED; the
# raw value from connect_ex() isn't normalised to the POSIX constant there.
_CONN_REFUSED_CODES = {errno.ECONNREFUSED, 10061}


def try_tcp_fallback(dest_ip: str, ttl: int, opts: Options) -> tuple[Probe, bool]:
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError:
        return Probe(method="tcp", timed_out=True), False

    outcome: "queue.Queue[tuple[bool, int]]" = queue.Queue(maxsize=1)
    sent = time.monotonic()

    def dial() -> None:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            tcp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            tcp_sock.settimeout(opts.timeout)
            err = tcp_sock.connect_ex((dest_ip, opts.tcp_fallback_port))
            outcome.put((err == 0 or err in _CONN_REFUSED_CODES, err))
        except OSError:
            outcome.put((False, -1))
        finally:
            tcp_sock.close()

    threading.Thread(target=dial, daemon=True).start()

    deadline = sent + opts.timeout
    dial_done = False

    try:
        while True:
            if not dial_done:
                try:
                    reached, _ = outcome.get_nowait()
                    dial_done = True
                    if reached:
                        # A SYN-ACK (open port) or RST (closed port) both
                        # mean the destination's own stack answered us.
                        return Probe(method="tcp", responder_ip=dest_ip, rtt=time.monotonic() - sent), True
                except queue.Empty:
                    pass

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return Probe(method="tcp", timed_out=True), False

            icmp_sock.settimeout(min(remaining, 0.05))
            try:
                data, addr = icmp_sock.recvfrom(1500)
            except (socket.timeout, OSError):
                continue

            rtt = time.monotonic() - sent
            _, icmp_bytes = split_ip_header(data)
            if len(icmp_bytes) < 8 or icmp_bytes[0] != 11:  # not Time Exceeded
                continue
            if _embedded_matches_tcp_probe(icmp_bytes[8:], dest_ip, opts.tcp_fallback_port):
                return Probe(method="tcp", responder_ip=addr[0], rtt=rtt), False
    finally:
        icmp_sock.close()


def _embedded_matches_tcp_probe(embedded: bytes, dest_ip: str, dest_port: int) -> bool:
    """Check whether a quoted-in-ICMP datagram was one of our TCP probes."""
    if len(embedded) < 20:
        return False
    ihl = (embedded[0] & 0x0F) * 4
    if len(embedded) < ihl + 4:
        return False
    if socket.inet_ntoa(embedded[16:20]) != dest_ip:
        return False
    dst_port = struct.unpack("!H", embedded[ihl + 2:ihl + 4])[0]
    return dst_port == dest_port
