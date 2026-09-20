"""Low-level helpers for building/parsing raw IP and ICMP packets."""

from __future__ import annotations


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def split_ip_header(data: bytes) -> tuple[int, bytes]:
    """Split a raw IPv4 datagram into (header length, payload)."""
    ihl = (data[0] & 0x0F) * 4
    return ihl, data[ihl:]
