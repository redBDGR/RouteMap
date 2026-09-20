"""Command-line entry point."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import socket
import sys
import time

from . import vault
from .icmp_trace import run as run_trace
from .models import Options, Result
from .targets import read_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routemap",
        description="Trace the network path to a list of targets and render an Obsidian vault.",
    )
    parser.add_argument("-targets", required=True, help="Path to a file listing target IPs/hostnames, one per line")
    parser.add_argument("-out", default="./vault", help="Output vault directory (default: ./vault)")
    parser.add_argument("-max-hops", dest="max_hops", type=int, default=30, help="Maximum TTL to probe (default: 30)")
    parser.add_argument("-probes", dest="probes", type=int, default=3, help="Probes sent per hop (default: 3)")
    parser.add_argument("-timeout", type=float, default=1.0, help="Per-probe timeout in seconds (default: 1.0)")
    parser.add_argument(
        "-tcp-fallback", dest="tcp_fallback", action="store_true", default=True,
        help="Fall back to TCP-connect probing on hops with zero ICMP replies (default: on)",
    )
    parser.add_argument(
        "-no-tcp-fallback", dest="tcp_fallback", action="store_false",
        help="Disable TCP fallback probing",
    )
    parser.add_argument("-tcp-port", dest="tcp_port", type=int, default=443, help="TCP port used for fallback probing (default: 443)")
    parser.add_argument("-concurrency", type=int, default=4, help="Targets traced in parallel (default: 4)")
    parser.add_argument("-json-out", dest="json_out", default="", help="Optional path to also dump raw results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        targets = read_targets(args.targets)
    except OSError as exc:
        print(f"routemap: reading targets file: {exc}", file=sys.stderr)
        return 1
    if not targets:
        print(f"routemap: no targets found in {args.targets}", file=sys.stderr)
        return 1

    # Bound DNS calls (hostname resolution, reverse lookups) so a single
    # unresponsive nameserver can't hang the whole run; raw ICMP/TCP sockets
    # set their own timeouts explicitly and are unaffected by this.
    socket.setdefaulttimeout(3.0)

    opts = Options(
        max_hops=args.max_hops,
        probes_per_hop=args.probes,
        timeout=args.timeout,
        tcp_fallback=args.tcp_fallback,
        tcp_fallback_port=args.tcp_port,
        concurrency=args.concurrency,
    )

    print(f"routemap: tracing {len(targets)} target(s)...")
    results: list[Result | None] = [None] * len(targets)

    def worker(index: int, target: str) -> None:
        start = time.monotonic()
        result = run_trace(target, opts)
        results[index] = result

        if result.error:
            status = f"error: {result.error}"
        elif result.reached:
            status = "reached"
        else:
            status = "unreachable"
        elapsed = time.monotonic() - start
        print(f"  {target:<30} {status:<11} ({elapsed:.2f}s, {len(result.hops)} hops)")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = [pool.submit(worker, i, t) for i, t in enumerate(targets)]
        for future in concurrent.futures.as_completed(futures):
            future.result()  # re-raise any unexpected exception

    print(f"routemap: building Obsidian vault at {args.out}...")
    vault.build(results, args.out)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump([dataclasses.asdict(r) for r in results], fh, indent=2)
        print(f"routemap: raw results written to {args.json_out}")

    print("routemap: done. Open the output folder as an Obsidian vault and start from Home.md.")
    return 0
