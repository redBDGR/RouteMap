from scapy.all import *
from scapy.layers.inet import *
from socket import *
import ipaddress
import requests
from bs4 import BeautifulSoup

# TO DO
# Convert target IP to  binary representation (demonstration purposes only)
# Conduct bgp.he.de IP looking for each hop/node

target = "18.155.229.82"
maxTTL = 30
debugOutput = False

def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
    
if __name__ == "__main__":
    print("")
    print(f"Tracing route to {target}")

    if is_ip(target):
        print(gethostbyaddr(target))

        # Print binary representation
        binaryRep = ""
        for i in target.split(sep='.'):
            binaryRep += f"{int(i):08b}."

        print(f"Target IP binary representation (8-bit): {binaryRep}")

        try:
            soup = BeautifulSoup(requests.get(f"https://bgp.he.net/ip/{target}").text, features="lxml")
            print(f"WAN IP subnet owned by: {soup.tbody.find_all('td')[2].text}")
        except Exception as e:
            print(e)

    else:
        print(gethostbyname(target))

    print()
    print("---------------! ICMP TRACEROUTE !-----------------")

    for i in range(1, maxTTL):

        # Construct UDP packets
        # Packets are sent with increasing TTLs.
        # As nodes recieve the packet, they reduce the TTL by 1.
        # If the node recieves a packet with a TTL of 1, it sends back a TTL end of life error back to the original sender (me), 
        # which can then be used to identify the hop IP
        pac = IP(dst=target, ttl=i) / ICMP()

        # Debug packet contents if required
        if debugOutput:
            if i == 1:
                pac.show()

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

        srcExpansion = ""
        try:
            if (not ipaddress.ip_address(src).is_private):
                srcExpansion = f" | {gethostbyaddr(src)}"
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
