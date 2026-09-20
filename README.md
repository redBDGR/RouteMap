# RouteMap

Traces the network path to a list of IPs/hostnames from a Windows endpoint
and renders the result as an Obsidian vault — a folder of linked markdown
notes that Obsidian's built-in Graph View turns into a visual network map,
no plugins required.

Pure Python standard library — no third-party runtime dependencies — built
to compile down to a single `routemap.exe` with PyInstaller.

## Usage

1. List targets, one per line, in a text file (see `targets.example.txt`).
2. Run the tool **as Administrator** (raw ICMP sockets require it):

   ```
   routemap.exe -targets targets.txt -out C:\NetworkMap
   ```
3. Open `C:\NetworkMap` as an Obsidian vault and start from `Home.md`. Switch
   to Graph View to see the topology.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-targets` | *(required)* | Path to the targets file |
| `-out` | `./vault` | Output vault directory |
| `-max-hops` | `30` | Maximum TTL to probe |
| `-probes` | `3` | Probes sent per hop |
| `-timeout` | `1.0` | Per-probe timeout (seconds) |
| `-tcp-fallback` / `-no-tcp-fallback` | on | Try a TCP-connect probe on hops with zero ICMP replies |
| `-tcp-port` | `443` | Port used for TCP fallback probes |
| `-concurrency` | `4` | Targets traced in parallel |
| `-json-out` | *(none)* | Also dump raw results to this JSON path, e.g. for attaching to a ticket |

## Building the .exe

PyInstaller does not cross-compile — it must run on the OS you're building
for. Since Windows is the only deployment target, build it on a Windows
machine or VM:

```
pip install -r requirements-dev.txt
pyinstaller routemap.spec
```

The exe is written to `dist/routemap.exe`.

If you don't have a Windows machine handy, push this repo to GitHub — the
included workflow (`.github/workflows/build.yml`) builds `routemap.exe` on
`windows-latest` on every push to `main` and uploads it as a downloadable
build artifact. Trigger it manually from the Actions tab
("Build Windows executable" → Run workflow) if you don't want to wait for a
push.

## Development

Runs directly with Python 3.9+ on any OS for local development/testing
(macOS/Linux need `sudo` for the same reason Windows needs Administrator —
raw ICMP sockets require elevated privileges everywhere):

```
sudo python3 main.py -targets targets.example.txt -out ./vault
```

Run the test suite (no elevated privileges required — the ICMP/TCP socket
logic is tested against a fake socket, not real ones):

```
python3 -m unittest discover -s tests
```

## Methodology

Standard traceroute (varying a port/ID per probe) gets unreliable on
networks with multiple equal-cost paths: successive probes can be
load-balanced onto different routes and the result stitches together hops
that were never on a single path together. RouteMap fixes the ICMP
identifier for the entire run against one target (the Paris-traceroute
technique) so every probe at every TTL is treated as the same flow.

ICMP is also commonly rate-limited or dropped by firewalls, particularly at
network edges, even when the same firewall happily forwards real traffic.
When a hop produces zero ICMP replies across all probes, RouteMap falls
back to a TCP-connect probe against the target's real service port
(443 by default). This deliberately avoids crafting raw TCP packets, which
Windows has blocked since XP SP2 and which would otherwise require
installing Npcap — instead it sets `IP_TTL` on a normal socket before
`connect()` and listens on a separate raw ICMP socket for the resulting
"Time Exceeded" reply, achieving the same result with nothing beyond local
admin rights.

A hop is only given up on after several consecutive fully-silent hops
(default 5), since a single unresponsive router does not mean the path
ends there — subsequent hops frequently still reply.

## Requirements

- Windows, run as Administrator (raw ICMP socket access).
- Outbound ICMP and TCP/443 (or your chosen fallback port) permitted on the
  local host firewall.

## Limitations

- IPv4 only.
- ECMP handling only fixes the ICMP identifier; it does not vary and probe
  all paths through a load balancer (i.e. it reports one consistent path,
  not every possible path).
- TCP fallback confirms a hop responded but reuses the destination's real
  port; it does not verify the service itself is healthy.
