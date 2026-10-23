# RouteMap

A small Python traceroute tool that maps the path to one or more targets, enriches each hop with WAN subnet ownership data, and writes the results out as an Obsidian vault so routes can be explored visually in graph view. It is a learning project, and the list below covers the skills it demonstrates.

## Demonstrated Knowledge

- **ICMP traceroute mechanics** - Sends ICMP echo requests with incrementing TTL values and reads the "time exceeded" replies to identify each hop. Stops when an echo reply (type 0) shows the target has been reached, or after `maxTTL` hops.
- **Raw packet crafting with Scapy** - Builds layered packets (`IP() / ICMP()`) and uses `sr1()` to send a packet and capture the first reply, with optional `show()` output for inspecting packet fields.
- **Resilient hop handling** - Treats timeouts as unresponsive hops (`*`) and continues the trace instead of aborting. The trace gives up after 10 consecutive unresponsive hops, and send errors are caught and reported.
- **IPv4 addressing and binary representation** - Splits an address into four 8-bit octets and prints each as binary to show how a 32-bit address is structured.
- **IP validation and classification** - Uses the `ipaddress` module to tell IPs from hostnames and to skip private (RFC 1918) addresses before doing public lookups.
- **DNS resolution** - Uses `socket` for forward (`gethostbyname`) and reverse (`gethostbyaddr`) lookups on the target.
- **Web scraping for network intelligence** - Fetches bgp.he.net IP pages with `requests` and parses the HTML with BeautifulSoup to find the organisation that owns each hop's subnet.
- **Command-line arguments** - Reads targets from `sys.argv` so several IPs or hostnames can be queued and traced in one run, falling back to a default target when none are given.
- **Graph modelling of network paths** - Stores each responding hop as an `Endpoint` object (IP and subnet owner) and links every hop to its upstream and downstream neighbours.
- **Generating an Obsidian vault** - Writes one Markdown note per hop using `pathlib`, with `[[wikilinks]]` to neighbouring hops. Notes are appended to rather than overwritten, so routes from multiple traces merge into a single network map.
- **Defensive coding** - Lookup failures return `None` instead of crashing, and a debug flag controls verbose packet output.

## Requirements

- Python 3
- `scapy`, `requests`, `beautifulsoup4`, `lxml` (install with `pip install -r requirements.txt`)
- Root/administrator privileges (needed to send raw packets)

## Usage

Pass one or more IPs or hostnames as arguments:

```
sudo python3 main.py 1.1.1.1 8.8.8.8 example.com
```

If no arguments are given, the `defaultTarget` set at the top of `main.py` is used. Other settings at the top of the file:

- `maxTTL` - maximum number of hops to probe (default 50)
- `debugOutput` - prints packet details and extra debug information

## Output

Each hop is written to the `test/` directory as `<ip> (<subnet owner>).md`, containing `Upstream:` and `Downstream:` links to its neighbouring hops. Open the folder as a vault in Obsidian and use graph view to see the routes.
