"""Data types shared across the tracing and vault-building modules."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Probe:
    """A single measurement attempt at a given TTL."""

    method: str = ""  # "icmp" or "tcp"
    responder_ip: str = ""  # empty if no reply was received
    rtt: float = 0.0  # seconds; meaningful only if responder_ip is set
    timed_out: bool = False


@dataclass
class Hop:
    """Every probe sent at a single TTL value."""

    ttl: int = 0
    probes: list[Probe] = field(default_factory=list)
    reached_destination: bool = False  # any probe at this TTL was answered directly by the destination


@dataclass
class Result:
    """The full traceroute outcome for one target."""

    target: str = ""  # as given by the user (hostname or IP)
    hostname: str = ""  # set if target was a hostname
    resolved_ip: str = ""
    hops: list[Hop] = field(default_factory=list)
    reached: bool = False
    error: str = ""


@dataclass
class Options:
    """Controls probing behaviour."""

    max_hops: int = 30
    probes_per_hop: int = 3
    timeout: float = 1.0  # seconds, per probe
    tcp_fallback: bool = True
    tcp_fallback_port: int = 443
    max_consecutive_silent_hops: int = 5  # stop after this many fully-silent hops in a row
    concurrency: int = 4  # targets traced in parallel
