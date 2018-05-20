#!/usr/bin/env python3
from scapy.all import * # sniffing module
import re

host_pattern = re.compile("Host:\s([a-zA-Z0-9.]+)")

_1m_file = open("/root/1m.txt","r")
block_sites = _1m_file.readlines()

b_sites = []
for site in block_sites:
    b_sites.append(site.splitlines()[0])

def binary_search(target, data):
    start = 0
    end = len(data) - 2

    while start <= end:
        mid = (start + end) // 2
        if data[mid] == target:
            return mid      # find block_site_idx
        elif data[mid] < target:
            start = mid + 1
        else:
            end = mid -1
    return None # NOPE!

#callback_func
def packet_callback(packet):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)
        if packet[IP].dport == 80:
            print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst, packet[IP].dport, str(bytes(packet[TCP].payload))))
            rawdata = str(bytes(packet[TCP].payload))
            host = host_pattern.search(rawdata)
            if host:
                idx = binary_search(host.group(1),b_sites)
                if idx >= 0:
                    print("Blocking!! -> ",b_sites[idx])

                elif idx == None:
                    print("GoodSite~ -> ",host.group(1))

sniff(filter="tcp", prn=packet_callback, store=0) # start sniffing
