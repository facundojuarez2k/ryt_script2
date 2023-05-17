import sys
import argparse
import random
from scapy.all import IP, TCP
import scapy.all as scapy

TCP_FLAGS = {
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80
}


def generate_private_port() -> int:
    return random.randint(49152, 65535)


def main():
    seq = random.randint(0, 2**32)
    ip_src = get_src_ip()
    ip_dst = "192.168.100.34"
    port_src = generate_private_port()
    port_dst = 80

    ip_packet = IP(src=ip_src, dst=ip_dst)
    tcp_segment = TCP(sport=port_src, dport=port_dst, flags="S", seq=seq)

    ans = scapy.sr1(ip_packet/tcp_segment, timeout=3)

    if ans is None or ans[TCP] is None:
        print("No response")
        exit(1)

    if ans[TCP].flags & TCP_FLAGS['SYN']:
        print("SYN-ACK")
    elif ans[TCP].flags & TCP_FLAGS['RST']:
        print("RST-ACK")

    flags_string = format_tcp_flags(ans[TCP].flags)

    print(flags_string)


def format_tcp_flags(int_value: int) -> str:
    '''
        Retorna una cadena de caracteres con las flags activas del encabezado TCP representadas por el argumento int_value
    '''

    output_string = ""

    for flag_name, flag_value in TCP_FLAGS.items():
        if int_value & flag_value:
            output_string += str(flag_name[0])

    return output_string


def get_src_ip(iface=scapy.conf.iface) -> str:
    ip = scapy.get_if_addr(iface)

    if ip is "0.0.0.0":
        raise Exception(
            f'Source IP address on interface {iface} not available')

    return ip


if __name__ == '__main__':
    main()
