"""ICMP-based traceroute with a fixed per-target flow identifier.

Standard traceroute varies a field (port/ID) on every probe, which lets
routers load-balancing across equal-cost paths (ECMP) hash successive
probes onto different routes — the result stitches together hops that were
never on one real path together. This keeps the ICMP identifier constant
for every probe sent to a given target (the Paris-traceroute technique) so
the whole run is treated as a single flow.
"""

from __future__ import annotations

import os
import platform
import socket
import struct
import time
import zlib

from .dns_utils import resolve
from .models import Hop, Options, Probe, Result
from .packet_utils import checksum, split_ip_header
from .tcp_fallback import try_tcp_fallback

_SESSION_SALT = os.getpid() & 0xFFFF


def run(target: str, opts: Options) -> Result:
    try:
        dest_ip, hostname = resolve(target)
    except (socket.gaierror, OSError) as exc:
        return Result(target=target, error=str(exc))

    result = Result(target=target, hostname=hostname, resolved_ip=dest_ip)

    if platform.system() == "Windows" and not _is_windows_admin():
        result.error = "raw ICMP sockets require running as Administrator"
        return result

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        result.error = "opening raw ICMP socket failed: run with elevated/root privileges"
        return result
    except OSError as exc:
        result.error = f"opening raw ICMP socket failed: {exc}"
        return result

    flow_id = _fixed_flow_id(target)
    seq = 0
    consecutive_silent = 0

    try:
        for ttl in range(1, opts.max_hops + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            hop = Hop(ttl=ttl)
            for _ in range(opts.probes_per_hop):
                seq += 1
                probe, reached = _send_probe(sock, dest_ip, flow_id, seq, opts.timeout)
                hop.probes.append(probe)
                if reached:
                    hop.reached_destination = True

            hop_fully_silent = all(p.timed_out for p in hop.probes)
            if hop_fully_silent and opts.tcp_fallback:
                tcp_probe, reached = try_tcp_fallback(dest_ip, ttl, opts)
                hop.probes.append(tcp_probe)
                if reached:
                    hop.reached_destination = True
                hop_fully_silent = all(p.timed_out for p in hop.probes)

            result.hops.append(hop)

            if hop.reached_destination:
                result.reached = True
                return result

            if hop_fully_silent:
                consecutive_silent += 1
                if consecutive_silent >= opts.max_consecutive_silent_hops:
                    break
            else:
                consecutive_silent = 0
    finally:
        sock.close()

    return result


def _fixed_flow_id(target: str) -> int:
    return (_SESSION_SALT ^ zlib.crc32(target.encode())) & 0xFFFF


def _build_echo_request(identifier: int, sequence: int, payload: bytes = b"routemap") -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", 8, 0, csum, identifier, sequence)
    return header + payload


def _send_probe(sock: socket.socket, dest_ip: str, identifier: int, seq: int, timeout: float) -> tuple[Probe, bool]:
    packet = _build_echo_request(identifier, seq)
    sent = time.monotonic()
    try:
        sock.sendto(packet, (dest_ip, 0))
    except OSError:
        return Probe(method="icmp", timed_out=True), False

    deadline = sent + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return Probe(method="icmp", timed_out=True), False

        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(1500)
        except (socket.timeout, OSError):
            return Probe(method="icmp", timed_out=True), False

        rtt = time.monotonic() - sent
        peer_ip = addr[0]
        _, icmp_bytes = split_ip_header(data)
        if len(icmp_bytes) < 8:
            continue

        icmp_type = icmp_bytes[0]
        if icmp_type == 11:  # Time Exceeded
            if _embedded_matches_echo(icmp_bytes[8:], identifier, seq):
                return Probe(method="icmp", responder_ip=peer_ip, rtt=rtt), False
        elif icmp_type == 0:  # Echo Reply
            _, _, _, got_id, got_seq = struct.unpack("!BBHHH", icmp_bytes[:8])
            if got_id == identifier and got_seq == seq:
                return Probe(method="icmp", responder_ip=peer_ip, rtt=rtt), peer_ip == dest_ip
        # else: unrelated ICMP traffic on the shared socket — keep waiting.


def _embedded_matches_echo(embedded: bytes, identifier: int, seq: int) -> bool:
    """Match the identifier/sequence quoted inside a Time Exceeded reply
    against the probe that triggered it."""
    if len(embedded) < 20:
        return False
    ihl = (embedded[0] & 0x0F) * 4
    if len(embedded) < ihl + 8:
        return False
    _, _, _, got_id, got_seq = struct.unpack("!BBHHH", embedded[ihl:ihl + 8])
    return got_id == identifier and got_seq == seq


def _is_windows_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
