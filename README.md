# SYN Test

## Requisitos

-   Python 3.6+
-   Scapy: `apt install python3-scapy`

## Ejecución

`sudo python3 syntest.py 10.0.15.30`

## Uso

```
usage: syntest.py [-h] [--count COUNT] [--port TARGET_PORT] target_ip_address

SYN Test

Sends a TCP segment with the SYN flag set.
- The target host may reply with a segment containing the RST and ACK flags set (RA) if no socket is using that port.
- If the remote host is listening on the target port, it should reply with the SYN and ACK flags set (SA).

positional arguments:
  target_ip_address     Destination host IP address

optional arguments:
  -h, --help            show this help message and exit
  --count COUNT, -c COUNT
                        Amount of TCP SYN segments to send. Allows integer
                        values greater than or equal to 0. Setting this flag
                        to 0 implies sending packets indefinitely. (Default:
                        0) (Optional)
  --port TARGET_PORT, -p TARGET_PORT
                        Target port to which the segment will be sent
                        (Default: 80)
```

## Ejemplos

#### Enviar 3 segmentos SYN a 192.168.50.3:22

`sudo python3 syntest.py 192.168.50.3 -c 3 -p 22`

#### Envíar segmentos SYN indefinidamente a la dirección IP 192.168.50.3:80

`sudo python3 syntest.py 192.168.50.3`

ó

`sudo python3 syntest.py 192.168.50.3`
