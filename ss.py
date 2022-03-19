#!/usr/bin/env python3
import socket
from typing import Any
from impacket.ImpactPacket import IP, TCP  # type: ignore
from random import randint


class Packet:
    def __init__(self, type_p, target, src_data) -> None:
        dst_ip, dst_port = target
        src_ip, src_port = src_data
        self.type_p = type_p
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.src_port = src_port

    def genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(self.src_ip)
        ip.set_ip_dst(self.dst_ip)
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_dport(self.dst_port)
        tcp.set_th_sport(randint(1, 65535))
        ip.contains(tcp)
        return ip.get_packet()


class Main:
    def __init__(self, type_p, target, src_data=('1.1.1.1', 80)) -> None:
        self.socket = self.start_socket()
        self.target = target
        self.src_data = src_data
        self.type_p = type_p

    def start_socket(self) -> Any:
        sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock

    def gen_packet(self, type_p, target, src_data) -> bytes:
        packet = Packet(type_p, target, src_data)
        return packet.genrate_syn()

    def sender(self) -> None:
        packet = self.gen_packet(self.type_p, self.target, self.src_data)
        self.socket.sendto(packet, self.target)
        self.socket.close()


if __name__ == '__main__':
    m = Main('SYN', ('216.58.215.110', 80))
    m.sender()
