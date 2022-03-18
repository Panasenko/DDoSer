#!/usr/bin/env python3
import socket
from Packet import Packet
from typing import Any


class Main:
    def __init__(self, type_p, target, src_data=('1.1.1.1', 8000)) -> None:
        self.socket = self.start_socket()
        self.target = target
        self.src_data = src_data
        self.type_p = type_p

    def start_socket(self) -> Any:
        with socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_TCP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock

    def gen_packet(self, type_p, target, src_data) -> bytes:
        packet = Packet(type_p, target, src_data)
        return packet.genrate_syn()

    def sender(self) -> None:
        self.socket.sendto(
                    self.gen_packet(
                                self.type_p,
                                self.target,
                                self.src_data
                                ), self.target)


if __name__ == '__main__':
    m = Main('SYN', ('216.58.215.110', 80))
    m.sender()
