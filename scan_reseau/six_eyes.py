import sys
import socket
import pyfiglet
from datetime import time
import argparse
from scapy.all import *
import random
from ipaddress import IPv4Network


""" 
 ____ _____  __  _______   _______ ____  
/ ___|_ _\ \/ / | ____\ \ / / ____/ ___| 
\___ \| | \  /  |  _|  \ V /|  _| \___ \ 
 ___) | | /  \  | |___  | | | |___ ___) |
|____/___/_/\_\ |_____| |_| |_____|____/ 

"""
    
ASCII_BANNER = pyfiglet.figlet_format("SIX EYES")


parser = argparse.ArgumentParser(description="scanneur de ports")
parser.add_argument("-ip", "--ipaddress", dest="ip_address", help="you need to specify an ip address")
parser.add_argument('-sS', "--syn-scan", dest='syn_scan', help="allow to send syn flag", required=False)
parser.add_argument('-SN', "--scan-network", dest='scan_networks', help="Allow you to scan an entire network")
parser.add_argument('-sU',"--udp-scan", dest="udp_scan", help="allows you to launch udp scan" )
parser.add_argument('-arp', "--arp", dest="arp_scan", help="Will try to see which hosts are up on the network")
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

def retrieve_arp(network: str):
    return arping(network)

    

def syn_scan(ip_address):
    for port in range(65536):
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=ip_address)/TCP(sport=src_port,dport=port,flags="S"), timeout=1, verbose=0)
        if resp is None:
            continue

        elif resp.haslayer(TCP):  
            #getlayer() utilisée pour récupérer une couche spécifique à partir d'un paquet réseau. Permet d'accéder directement à une couche particulière 
            #d'un paquet afin d'effectuer des opérations spécifiques 
            if(resp.getlayer(TCP).flags == 0x12): #or resp.getlayer(TCP.flags == 0x24):
                send_rst = sr(IP(dst=ip_address) / TCP(sport=src_port,dport=port, flags='R'), timeout=1,verbose=0)
                print(f"{port} open/TCP")

            # 0x14 RST 0x04 + ACK 0x10
            elif(resp.getlayer(TCP).flags == 0x14):
                print(f"{ip_address}:{port} closed/TCP")
        
        elif(resp.haslayer(ICMP)):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]):
                print(f"{ip_address} : {port} is filtered") 

def scan_network(network : str):
    try:
        addresses = IPv4Network(network)
        for address in addresses:
            if (address in(addresses.network_address, addresses.broadcast_address)):
                #Skip the broadcast address and the network address
                continue
            
            resp = sr1(IP(dst=str(address))/ICMP(), timeout=1)
            # Rappel : continue permet de passer directement à l'itération suivante sans même exécuter la suite du code
            if resp is None:
                continue
            elif(resp.haslayer(ICMP)):
                if(int(resp.getlayer(ICMP).type) == 0):
                    print(f"{address} host is up")
            
                
    except ValueError:
        print("Be sure to enter a network with a valide mask like this :\n 192.168.0.0/32")


def udp_scan(ip_address : str):
    for port in range(65536):
        src_port = random.randint(1025,65534)
        resp = sr1(IP(dst=ip_address) / UDP())

        if resp is None or resp.haslayer(UDP):
            print(f"{port} open/udp")


def wifi_probe_request(mac_address : str):
    # RadioTap() permet de créer et de manipuler des en-têtes RadioTap.
    # RadiotTap est un en-tête utilisé dans les trames Wi-Fi pour encapsuler des métadonnées liées à la capture du paquet par une interface Radio
    packet = 

    
# https://nmap.org/man/fr/man-version-detection.html

def scan_version(ip_address : str):
    pass



if __name__ == '__main__':
    print(ASCII_BANNER)
    if args.ip_address:
        scan_ports(sys.argv[2])
    if args.scan_networks:
        scan_network(sys.argv[2])
    if args.syn_scan:
        syn_scan(sys.argv[2])
    if args.arp_scan:
        retrieve_arp(sys.argv[2])

