# RouteMap

A small Python traceroute tool that maps the path to a target IP and enriches each hop with WAN subnet ownership data. It is a learning project, and the list below covers the skills it demonstrates.

## Demonstrated Knowledge

- **ICMP traceroute mechanics** - Sends ICMP echo requests with incrementing TTL values and reads the "time exceeded" replies to identify each hop. Stops when an echo reply (type 0) shows the target has been reached.
- **Raw packet crafting with Scapy** - Builds layered packets (`IP() / ICMP()`) and uses `sr1()` to send a packet and capture the first reply, with optional `show()` output for inspecting packet fields.
- **Resilient hop handling** - Treats timeouts as unresponsive hops (`*`) and continues the trace instead of aborting. Send errors are caught and reported.
- **IPv4 addressing and binary representation** - Splits an address into four 8-bit octets and prints each as binary to show how a 32-bit address is structured.
- **IP validation and classification** - Uses the `ipaddress` module to tell IPs from hostnames and to skip private (RFC 1918) addresses before doing public lookups.
- **DNS resolution** - Uses `socket` for forward (`gethostbyname`) and reverse (`gethostbyaddr`) lookups on the target.
- **Web scraping for network intelligence** - Fetches bgp.he.net IP pages with `requests` and parses the HTML with BeautifulSoup to find the organisation that owns each hop's subnet.
- **Defensive coding** - Lookup failures return `None` instead of crashing, and a debug flag controls verbose packet output.

## Requirements

- Python 3
- `scapy`, `requests`, `beautifulsoup4`, `lxml`
- Root/administrator privileges (needed to send raw packets)

## Usage

Set `target` at the top of `main.py`, then run:

```
sudo python3 main.py
```
