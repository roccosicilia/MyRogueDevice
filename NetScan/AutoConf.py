#
# NIC auto-conf script
#

# lib
from scapy.all import *
import sys

# setup
if len(sys.argv) >= 2:
    adapter = sys.argv[1]
else:
    adapter = 'eth0' # change if different

# arp sniff func
sniffer_timeout = 30
captured_pkt = []
def arp_sniff(packet):
    if ARP in packet and packet[ARP].op == 1:
        captured_pkt.append(packet)

sniff(iface=adapter, filter='arp', prn=arp_sniff, timeout=sniffer_timeout)

print("#"*75)
print("Sniffed ARP packets on {}: {}".format(adapter, len(captured_pkt)))
print(captured_pkt)

for frame in captured_pkt:
    single_packet = str(frame).split(">,")
    for x in single_packet:
        print(frame)
    print("-----")
