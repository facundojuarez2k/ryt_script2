import sys
import argparse
import random
import re
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
    try:
        args = parse_args()
    except ValueError as ex1:
        print(f'ERROR: {str(ex1)}', file=sys.stderr)
        return 0

    seq = random.randint(0, 2**32)
    ip_src = get_src_ip()
    port_src = generate_private_port()

    ip_packet = IP(src=ip_src, dst=args.target_ip_address)
    tcp_segment = TCP(sport=port_src, dport=args.target_port, flags="S", seq=seq)

    ans = scapy.sr1(ip_packet/tcp_segment, timeout=3, verbose=0)

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


def parse_args() -> object:
    '''
    Captura y retorna los argumentos del programa
    '''
    parser = argparse.ArgumentParser(description='ARP Ping')
    parser.add_argument(dest='target_ip_address', type=str,
                        help='Destination host IP address')
    parser.add_argument('--count', '-c', dest='count', type=int,
                        help='Amount of TCP SYN segments to send. Allows integer values greater than or equal to 0. Setting this flag to 0 implies sending packets indefinitely. (Default = 0) (Optional)', default=0)
    parser.add_argument('--port', '-p', dest='target_port', type=int,
                        help='Remote port to which the segment will be sent (Default: 80)', default=80)

    validate_args(parser.parse_args())

    return parser.parse_args()


def validate_args(args: object) -> None:
    '''
    Valida los argumentos del programa
    '''
    if args.count < 0:
        raise ValueError(
            'Argument "count" must be an integer value greater than or equal to 0.')
    if is_valid_ipv4(args.target_ip_address) is False:
        raise ValueError(
            f'Value {args.target_ip_address} is not a valid IPv4 address.')
    if args.target_port < 0 or args.target_port > 65535:
        raise ValueError(
            f'Invalid port number {args.port}.')


def is_valid_ipv4(address: str) -> bool:
    '''
    Retorna True si la cadena de caracteres address es una dirección IPv4 válida en formato dot-decimal (ej. 190.30.2.5)
    '''
    ipv4_address_format = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    match = re.fullmatch(ipv4_address_format, address)
    return match is not None


if __name__ == '__main__':
    main()
