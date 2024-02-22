#
# NIC auto-conf script
#

# lib
from scapy.all import *
import sys

# arp sniff func
sniffer_timeout = 15
captured_pkt = []
def arp_sniff(packet):
    if ARP in packet and packet[ARP].op == 1:
        captured_pkt.append(packet)

sniff(iface=adapter, filter='arp', prn=arp_sniff, timeout=sniffer_timeout)

print("+---------------------------------------------+")
print("Sniffed ARP packets on {}: {}".format(adapter, len(captured_pkt)))
print(captured_pkt)
