"""Renders traceroute results as a plain folder of markdown notes, wikilinked
so Obsidian's built-in Graph View draws the topology with no plugins or
vault configuration required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .dns_utils import is_private, reverse_lookup
from .models import Hop, Result

_SANITIZE_RE = re.compile(r'[\\/:*?"<>|]')


@dataclass
class _EdgeContext:
    target: str
    skipped: int = 0


@dataclass
class _NodeRecord:
    ip: str
    hostname: str = ""
    private: bool = False
    targets: set[str] = field(default_factory=set)
    is_destination: set[str] = field(default_factory=set)
    edges: dict[str, list[_EdgeContext]] = field(default_factory=dict)


@dataclass
class _ChainEntry:
    ip: str
    ttl: int
    rtt_ms: float
    skipped_before: int


def build(results: list[Result], out_dir: str) -> None:
    """Write a full vault (Nodes/, Targets/, Home.md) under out_dir."""
    out = Path(out_dir)
    nodes_dir = out / "Nodes"
    targets_dir = out / "Targets"
    for d in (out, nodes_dir, targets_dir):
        d.mkdir(parents=True, exist_ok=True)

    nodes: dict[str, _NodeRecord] = {}

    def get_node(ip: str) -> _NodeRecord:
        if ip not in nodes:
            nodes[ip] = _NodeRecord(ip=ip, hostname=reverse_lookup(ip), private=is_private(ip))
        return nodes[ip]

    for result in results:
        chain = _build_chain(result)
        for i, entry in enumerate(chain):
            node = get_node(entry.ip)
            node.targets.add(result.target)
            if result.reached and i == len(chain) - 1 and entry.ip == result.resolved_ip:
                node.is_destination.add(result.target)
            if i + 1 < len(chain):
                nxt = chain[i + 1]
                node.edges.setdefault(nxt.ip, []).append(
                    _EdgeContext(target=result.target, skipped=nxt.skipped_before)
                )

    for result in results:
        _write_target_note(targets_dir, result)
    for node in nodes.values():
        _write_node_note(nodes_dir, node, nodes)
    _write_home_note(out, results, nodes)


def _sanitize(name: str) -> str:
    return _SANITIZE_RE.sub("-", name)


def _node_link(ip: str) -> str:
    return f"[[{_sanitize(ip)}]]"


def _target_title(target: str) -> str:
    return f"Target - {_sanitize(target)}"


def _target_link(target: str) -> str:
    return f"[[{_target_title(target)}]]"


def _best_responder(hop: Hop) -> tuple[str, float] | None:
    """Pick the IP that answered the most probes at this hop (majority vote
    across ICMP/TCP probes) and return its average RTT in milliseconds."""
    order: list[str] = []
    rtts: dict[str, list[float]] = {}
    for probe in hop.probes:
        if not probe.responder_ip:
            continue
        if probe.responder_ip not in rtts:
            order.append(probe.responder_ip)
            rtts[probe.responder_ip] = []
        rtts[probe.responder_ip].append(probe.rtt)
    if not order:
        return None
    best = max(order, key=lambda ip: len(rtts[ip]))
    avg = sum(rtts[best]) / len(rtts[best])
    return best, avg * 1000.0


def _build_chain(result: Result) -> list[_ChainEntry]:
    """Reduce a Result's hops to the ones that actually responded, skipping
    (but counting) silent hops so the graph links nearest-known-node to
    nearest-known-node rather than including meaningless placeholders."""
    chain: list[_ChainEntry] = []
    skipped = 0
    for hop in result.hops:
        best = _best_responder(hop)
        if best is None:
            skipped += 1
            continue
        ip, rtt_ms = best
        chain.append(_ChainEntry(ip=ip, ttl=hop.ttl, rtt_ms=rtt_ms, skipped_before=skipped))
        skipped = 0
    return chain


def _write_target_note(dir_: Path, result: Result) -> None:
    lines = [f"# Target: {result.target}", ""]
    if result.resolved_ip:
        lines += [f"**Resolved IP:** {result.resolved_ip}", ""]
    if result.error:
        lines += [f"**Error:** {result.error}", ""]
    lines += [f"**Reached:** {'Yes' if result.reached else 'No'}", ""]

    chain = _build_chain(result)
    if chain:
        lines.append("## Path")
        lines.append("")
        for i, entry in enumerate(chain):
            note = ""
            if entry.skipped_before:
                note = f" ({entry.skipped_before} unresponsive hop(s) before this)"
            if i == len(chain) - 1 and result.reached:
                note += " — destination"
            lines.append(f"{i + 1}. {_node_link(entry.ip)} — {entry.rtt_ms:.1f}ms{note}")
        lines.append("")

    (dir_ / f"{_target_title(result.target)}.md").write_text("\n".join(lines), encoding="utf-8")


def _edge_line(arrow: str, neighbour_ip: str, ctx: _EdgeContext) -> str:
    skip = f", {ctx.skipped} unresponsive hop(s) skipped" if ctx.skipped else ""
    return f"- {arrow} {_node_link(neighbour_ip)} (via {_target_link(ctx.target)}{skip})"


def _sorted_target_links(targets: set[str]) -> str:
    return ", ".join(_target_link(t) for t in sorted(targets))


def _write_node_note(dir_: Path, node: _NodeRecord, all_nodes: dict[str, _NodeRecord]) -> None:
    lines = [f"# {node.ip}", ""]
    if node.hostname:
        lines += [f"**Hostname:** {node.hostname}", ""]
    lines += [f"**Type:** {'Internal (private address space)' if node.private else 'External'}", ""]

    if node.is_destination:
        lines += [f"**Destination for:** {_sorted_target_links(node.is_destination)}", ""]
    if node.targets:
        lines += [f"**Seen as a hop while tracing:** {_sorted_target_links(node.targets)}", ""]

    incoming = [
        _edge_line("←", other_ip, ctx)
        for other_ip, other in all_nodes.items()
        for ctx in other.edges.get(node.ip, [])
    ]
    outgoing = [
        _edge_line("→", neighbour_ip, ctx)
        for neighbour_ip, contexts in node.edges.items()
        for ctx in contexts
    ]

    if incoming or outgoing:
        lines.append("## Connections")
        lines.append("")
        lines += sorted(incoming) + sorted(outgoing)
        lines.append("")

    (dir_ / f"{_sanitize(node.ip)}.md").write_text("\n".join(lines), encoding="utf-8")


def _write_home_note(out: Path, results: list[Result], nodes: dict[str, _NodeRecord]) -> None:
    lines = ["# Network Map", ""]
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"**Targets traced:** {len(results)}")
    lines.append("")
    lines.append("## Targets")
    lines.append("")
    for result in results:
        status = "reached" if result.reached else "not reached"
        lines.append(f"- {_target_link(result.target)} — {status}")
    lines.append("")
    lines.append("## All discovered nodes")
    lines.append("")
    for ip in sorted(nodes):
        node = nodes[ip]
        label = _node_link(ip)
        if node.hostname:
            label += f" ({node.hostname})"
        lines.append(f"- {label}")

    (out / "Home.md").write_text("\n".join(lines), encoding="utf-8")
