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
def arp_scan(target_ip, interface):

    # packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)
    answer, _ = srp(arp_request, timeout=2, iface=interface, verbose=True)

    # JSON output
    result = []
    for sent, received in answer:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})
    
    return result

# main script

for target in target_list:
    scan_result = arp_scan(target, adapter)
    for entry in scan_result:
        print("IP: {}, MAC: {}".format(entry['IP'], entry['MAC']))
