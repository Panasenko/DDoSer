#!/usr/bin/env python3

from socket import (AF_INET, IPPROTO_TCP, SOCK_RAW, socket, IPPROTO_IP, IP_HDRINCL)
from impacket.ImpactPacket import IP, TCP
from random import randint

def genrate_syn() -> bytes:
    ip: IP = IP()
    ip.set_ip_src('1.1.1.1')
    ip.set_ip_dst('216.58.215.110')
    tcp: TCP = TCP()
    tcp.set_SYN()
    tcp.set_th_dport(80)
    tcp.set_th_sport(8000)
    ip.contains(tcp)
    return ip.get_packet()

s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.sendto(genrate_syn(), ("216.58.215.110", 80))
