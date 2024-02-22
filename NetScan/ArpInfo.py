#
# get information via arp requests
#

# lib
from scapy.all import *
import sys

# setup
if len(sys.argv) >= 3:
    target_list = sys.argv[1]
    adapter = sys.argv[2]
else:
    target_list = '192.168.0.0/24'
    adapter = 'eth1' # change if different

# arp scan
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_list)
ans,uans = srp(arp_request, timeout=2, iface=adapter, verbose=False)

print("+---------------------------------------------+")
print("IP list from arp-scan")
result = []
for sent, received in ans:
    result.append({'IP': received.psrc, 'MAC': received.hwsrc})

# arp scan output
for entry in result:
    print(entry)

# arp sniff func
sniffer_timeout = 10
captured_pkt = []
def arp_sniff(packet):
    if ARP in packet and packet[ARP].op == 1:
        captured_pkt.append(packet)

sniff(filter='arp', prn=arp_sniff, timeout=sniffer_timeout)

print("+---------------------------------------------+")
print("Sniffed ARP packets: {}".format(len(captured_pkt)))
print(captured_pkt)
