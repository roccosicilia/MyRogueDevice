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
#print(captured_pkt)

# print ARP frame list
print("#"*75)
for frame in captured_pkt:
    print(frame)
    print("-----")

# define IP list
ip_list = []
for frame in captured_pkt:
    single_frame = str(frame).split(" ")
    ip_list.append(single_frame[5])
    ip_list.append(single_frame[7])
print(ip_list)

mygw = max(ip_list, key=ip_list.count)
print(mygw)
