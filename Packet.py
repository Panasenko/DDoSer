from impacket.ImpactPacket import IP, TCP  # type: ignore


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
        tcp.set_th_sport(self.src_port)
        ip.contains(tcp)
        return ip.get_packet()
