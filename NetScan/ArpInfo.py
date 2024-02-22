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
    target_list = ['192.168.0.0/24', '172.16.0.0/20']
    adapter = 'eth1' # change if different

# arp scan
result = []
for target in target_list:
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target)
    ans,uans = srp(arp_request, timeout=2, iface=adapter, verbose=False)
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

# arp scan output
for entry in result:
    print(entry)

# arp sniff
