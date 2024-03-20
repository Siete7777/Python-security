import sys
import socket
import pyfiglet
from datetime import datetime
import argparse

# 1. Allow user to specify target 
# 2. Make requests to every port
# 3. Return open ports


parser = argparse.ArgumentParser(description="scanneur de ports")
parser.add_argument("-ip", "--ipaddress", help="you need to specify an ip address", required=True)
args = parser.parse_args()


def scan_ports(ip_adress):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        for port in range(1, 65536):
            if s.connect_ex((ip_adress, port)) == 0 :
                print(f"[*] Port {port} is open")
    except ConnectionError:
        print("Une erreur de connexion s'est produite")


if __name__ == '__main__':
    ascii_banner = pyfiglet.figlet_format("SIX EYES")
    print(ascii_banner)

    scan_ports(sys.argv[2])

