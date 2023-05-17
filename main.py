import sys
import argparse
from scapy.all import IP, TCP, sr1


def main():
    ip_packet = IP(src="192.168.100.34", dst="192.168.100.31")
    tcp_segment = TCP(sport=5000, dport=2500, flags="S", seq=300)
    ans = sr1(ip_packet/tcp_segment, timeout=3)
    print(format_flags(ans[TCP].flags))


def format_flags(int_value: int) -> str:
    '''
        Retorna una cadena de caracteres con las flags activas del encabezado TCP representadas por el argumento int_value
    '''
    flags = {
        'F': 0x01,  # FIN
        'S': 0x02,  # SYN
        'R': 0x04,  # RST
        'P': 0x08,  # PSH
        'A': 0x10,  # ACK
        'U': 0x20,  # URG
        'E': 0x40,  # ECE
        'C': 0x80  # CWR
    }

    output_string = ""

    for flag_name, flag_value in flags.items():
        if int_value & flag_value:
            output_string = f'{output_string}{flag_name}'

    return output_string


if __name__ == '__main__':
    main()
