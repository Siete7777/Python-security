import sys
import socket
import pyfiglet
from datetime import time
import argparse
from scapy.all import *
import random


# 1. Allow user to specify target 
# 2. Make requests to every port
# 3. Return open ports


parser = argparse.ArgumentParser(description="scanneur de ports")
parser.add_argument("-ip", "--ipaddress", dest="ip_address", help="you need to specify an ip address", required=True)
#dest : specify the attribute name used in the result namespace, utilisé pour spécifier le nom de l'attribut dans lequel la valeur de
# l'argument doit être stockée une fois qu'il est analysé.
args = parser.parse_args()


def scan_ports(ip_adress):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        for port in range(1, 65536):
            if s.connect_ex((ip_adress, port)) == 0:
                #time.sleep(1)
                print(f"[*] Port {port} is open")
    except ConnectionError:
        print("Une erreur de connexion s'est produite")

#haslayer() méthode utilisée pour vérifier si un paquet réseau possède une couche spécifique. Cette méthode renvoie un booléen.

def syn_scan(ip_address):
    for i in range(65536):
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=ip_address)/TCP(sport=src_port,dport=i,flags="S"), timeout=1, verbose=0)
        if resp is None:
            print(f"{ip_address}:{i} is filtered.")

        elif resp.haslayer(TCP):  
            #getlayer() utilisée pour récupérer une couche spécifique à partir d'un paquet réseau. Permet d'accéder directement à une couche particulière 
            #d'un paquet afin d'effectuer des opérations spécifiques 
            if resp.getlayer((TCP).flags == 0x12):
            
    
    



if __name__ == '__main__':
    ascii_banner = pyfiglet.figlet_format("SIX EYES")
    print(ascii_banner)
    if args.ip_address:
        scan_ports(sys.argv[2])

