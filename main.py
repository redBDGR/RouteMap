from scapy.all import *
from scapy.layers.inet import *
from socket import *
import ipaddress
import requests
from bs4 import BeautifulSoup

# TO DO
# Convert target IP to  binary representation (demonstration purposes only)
# Conduct bgp.he.de IP looking for each hop/node

target = "14.200.195.182"
maxTTL = 30
debugOutput = False

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# Scrape BGP.he.de IP lookup page for WAN IP address/subnet owner
def lookup_wansubnet_owner(target):
    try:
        soup = BeautifulSoup(requests.get(f"https://bgp.he.net/ip/{target}").text, features="lxml")
        return soup.tbody.find_all('td')[2].text
    except Exception as e:
        return None
    
if __name__ == "__main__":
    print("")
    print(f"Tracing route to {target}")

    if is_ip(target):
        print(gethostbyaddr(target))

        # Print binary representation
        # Constructs a list of 4x 8-bit octects (32-bit IPv4 address split)
        binaryRep = []
        for i in target.split(sep='.'):
            binaryRep.append(f"{int(i):08b}")

        # Rejoins octects and adds a . inbetween to visualise the data easier
        print(f"Target IP binary representation (8-bit): {'.'.join(binaryRep)}")

        # Conducts WAN IP subnet owner lookup using BGP.he.de IP web page scape
        print(f"WAN IP subnet owned by: {lookup_wansubnet_owner(target=target)}")

    else:
        print(gethostbyname(target))

    print()
    print("---------------! ICMP TRACEROUTE !-----------------")

    for i in range(0, maxTTL):

        # Construct UDP packets
        # Packets are sent with increasing TTLs.
        # As nodes recieve the packet, they reduce the TTL by 1.
        # If the node recieves a packet with a TTL of 1, it sends back a TTL end of life error back to the original sender (me), 
        # which can then be used to identify the hop IP
        pac = IP(dst=target, ttl=i) / ICMP()

        # Debug packet contents if required
        if i == 0:
            if debugOutput:
                pac.show()
            print (f"HOP: {i} | SRC: {pac.src} | TYPE: 11")
            continue

        # Try to send packet and recieve response
        try:
            reply = sr1(pac, timeout=2, verbose=0)

        # Catch exception and log fault to console
        except Exception as e:
            print(f"Error when sending packet: {e}")
            break

        if reply is None:
            print(f"HOP: {i} | * (NO RESPNOSE)")
            continue

        src = reply.fields["src"]
        type = reply[ICMP].type

        # Attempt WAN subnet owner resolution
        srcExpansion = ""
        try:
            if (not ipaddress.ip_address(src).is_private):
                owner = lookup_wansubnet_owner(src)
                if owner != None:
                    srcExpansion = f" | {owner}"
        except:
            srcExpansion = ""

        # Print trace route entry
        print (f"HOP: {i} | SRC: {src} {srcExpansion} | TYPE: {type}")

        if (type == 0):
            print("---------------------------------------------------")
            print()
            break

    # List packet variables/data
    #ls(packet)
