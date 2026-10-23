from scapy.all import *
from scapy.layers.inet import *
from socket import *
import ipaddress
import requests
from bs4 import BeautifulSoup
from pathlib import Path
import sys

# TO DO
# Create an Obsidian vault directory of all hops to visually display the route process and routing links

defaultTarget = "59.154.68.146"
maxTTL = 50
debugOutput = False

# Validates if a variable is an IP
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

# Conducts initial host/IP lookups and prints to console
def print_host_information(target):
    try:
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
            print(f"WAN IP owned by: {lookup_wansubnet_owner(target=target)}")
        else:
            print(gethostbyname(target))

    except Exception as e:
        print (f"Host information not found ({e})")

    return

# Performs a traceroute, returns a list of Endpoint objects
def execute_traceroute(target):
    print()
    print("---------------! ICMP TRACEROUTE !-----------------")
    print()

    endpointList = []
    failedHopIncrement = 0

    for i in range(0, maxTTL):

        # If max number of failed hops has been reached, cancel the scan
        if failedHopIncrement == 10:
            break
        
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
            print(f"HOP: {i} | * (NO RESPNOSE) *")
            failedHopIncrement += 1
            continue
        else:
            # Reset failed hop count
            failedHopIncrement = 0

        src = reply.fields["src"]
        type = reply[ICMP].type

        # Attempt WAN subnet owner resolution
        srcExpansion = ""
        owner = ""
        try:
            if (not ipaddress.ip_address(src).is_private):
                owner = lookup_wansubnet_owner(src)
                if owner != None:
                    srcExpansion = f" | {owner}"
                else:
                    owner = "Unknown"
        except:
            srcExpansion = ""

        # Print trace route entry
        print (f"HOP: {i} | SRC: {src} {srcExpansion} | TYPE: {type}")

        # Add hop to indexing list
        endpointList.append(Endpoint(src, owner))

        if (type == 0):
            print()
            print("---------------------------------------------------")
            print()
            break
    return endpointList

# Writes a list of Endpoint objects to the directory specified
def write_obsidian_output(hops):
    # Construct obsidian web
    for i in range(0, len(hops)):
        e = hops[i]

        downstreamEndpoint = None
        upstreamEndpoint = None

        # Find previous hop
        if i > 0:
            downstreamEndpoint = hops[i-1]

        # Find next hop
        if i < len(hops) - 1:
            upstreamEndpoint = hops[i+1]

        # Debug outputs
        if debugOutput:
            print (e.ip)

        outputFile = Path(f"test/{e.ip} ({e.subnetOwner}).md")
        outputFile.parent.mkdir(parents=True, exist_ok=True)

        with outputFile.open("a+") as file:
            if upstreamEndpoint != None:
                writeString = f"Upstream: [[{upstreamEndpoint.ip} ({upstreamEndpoint.subnetOwner})]]"

                # Check if upstream has already been written to this file before
                if writeString not in file.read():
                    file.write(f"{writeString}\n")

            if downstreamEndpoint != None:
                writeString = f"Downstream: [[{downstreamEndpoint.ip} ({downstreamEndpoint.subnetOwner})]]"

                # Check if downstream has already been written to this file before
                if writeString not in file.read():
                    file.write(f"{writeString}\n")    

class Endpoint:
    def __init__(self, ip, subnetOwner):
        self.ip = ip
        self.subnetOwner = subnetOwner

    def ip(self):
        return self.ip

    def subnetOwner(self):
        return self.subnetOwner

def main(args:list):
    ipList = args[1:]
    if len(ipList) == 0:
        ipList.append(defaultTarget)

    for target in ipList:
        print("")
        print(f"! Initiating trace route to {target} !")

        print_host_information(target=target)

        endpointList = execute_traceroute(target=target)

        write_obsidian_output(endpointList)
    
    
if __name__ == "__main__":
    main(sys.argv)

    # List packet variables/data
    #ls(packet)
