#
# get information via arp requests
#

# lib
from scapy.all import *
import sys

# setup
if sys.argv[1] == None:
    target_list = ['192.168.0.0/24', '10.25.82.0/24']
else:
    target_list = sys.argv[1]
if sys.argv[2] == None:
    adapter = 'eth0'
else:
    adapter = sys.argv[2]

# arp scan
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_list)
ans,uans = srp(arp_request, timeout=2, iface=adapter, verbose=False)

result = []
for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

# arp scan output
for entry in result:
        print(entry)
        