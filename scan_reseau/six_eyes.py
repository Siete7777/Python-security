import sys
import socket
import pyfiglet
from datetime import time
import argparse
from scapy.all import *
import random
from ipaddress import IPv4Network

# 1. Allow user to specify target 
# 2. Make requests to every port
# 3. Return open ports



"""
URG (Urgent) : Ce drapeau indique que les données urgentes sont présentes dans le segment TCP.

Code : 0x20 (32 en décimal)
ACK (Acknowledgment) : Ce drapeau indique que le numéro d'acquittement (ACK) est valide.

Code : 0x10 (16 en décimal)
PSH (Push) : Ce drapeau indique que les données doivent être poussées vers l'application destinataire dès qu'elles sont disponibles, sans attendre de remplir le tampon de sortie.

Code : 0x08 (8 en décimal)
RST (Reset) : Ce drapeau indique une demande de réinitialisation de la connexion.

Code : 0x04 (4 en décimal)
SYN (Synchronize) : Ce drapeau est utilisé lors de l'établissement de la connexion TCP pour synchroniser les numéros de séquence.

Code : 0x02 (2 en décimal)
FIN (Finish) : Ce drapeau indique la fin d'une connexion TCP.

Code : 0x01 (1 en décimal)
"""

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
#dest : specify the attribute name used in the result namespace, utilisé pour spécifier le nom de l'attribut dans lequel la valeur de
# l'argument doit être stockée une fois qu'il est analysé.
parser.add_argument('-sS', "--syn-scan", dest='syn_scan', help="allow to send syn flag", required=False)
parser.add_argument('-SN', "--scan-network", dest='scan_networks', help="Allow you to scan an entire network")
args = parser.parse_args()


def scan_ports(ip_adress):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #AF_INET fait référence à la famille d'adresses IPV4. On utilise des adresses au format IPV4 pour communiquer
    # SOCK_STREAM est utilisé pour les sockets de type flux. Cela signifie que les données sont transférés dans un flux continu de bytes. Ces sockets utilisent le protocole TCP
    try:
        for port in range(1, 65536):
            if s.connect_ex((ip_adress, port)) == 0:
                #time.sleep(1)
                print(f"[*] Port {port} is open")
    except ConnectionError:
        print("Une erreur de connexion s'est produite")

#haslayer() méthode utilisée pour vérifier si un paquet réseau possède une couche spécifique. Cette méthode renvoie un booléen.

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
                # verbose est utilisé pour contrôler la quantité de sortie affichée lors de l'exécution de certaines commandes ou fonctions
                # veborse a 4 niveaux (0,1,2,3)
                # 0 : mode silencieux
                # 1 : affiche les erreurs et les avertissements
                # 2 : affiche des informations supplémentaires lors de l'exécution des commandes.
                # 3 ou supérieur : affiche les informations de débogage détaillées.
                #
                # timeout : est utilisé pour sépcifier la durée maximale d'attente pour cetaines opérations dans scapy. Donc timeout=1 signifie que Scapy 
                # attendra au maximum une seconde avant de considérer l'opération comme ayant échouée. 
                print(f"{port} open/TCP")

            # 0x14 RST 0x04 + ACK 0x10
            elif(resp.getlayer(TCP).flags == 0x14):
                print(f"{ip_address}:{port} closed/TCP")
        
        elif(resp.haslayer(ICMP)):
            # resp.getlayer(ICMP).type va renvoyer l'en-tête ICMP contenu dans cette couche
            # L'en-tête ICMP peut prendre plusieurs valeurs qui correspond à différents messages ICMP :
            # 0 : Echo reply (réponse à la demande Echo)
            # 3 : Destination Unreachable (Destination inaccessible)
            # 8 : Echo Request (demande Echo)
            # 11 : Time Exceeded (délai dépassé)
            
            # resp.getlayer(ICMP).code renvoie le code associé à l'en-tête contenu dans la couche ICMP du paquet resp
            # le code est une valeur qui accompagne le type dans certains messages ICMP pour fournir plus d'informations sur la nature
            # de l'erreur
            # Par exemple, dans les messages ICMP de type "Destination Unreachable", 
            # #le code peut indiquer la raison spécifique pour laquelle la destination est inaccessible, 
            # comme "Host Unreachable" (code 1) ou "Port Unreachable" (code 3).
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
                             
    
    



if __name__ == '__main__':
    print(ASCII_BANNER)
    if args.ip_address:
        scan_ports(sys.argv[2])
    if args.scan_networks:
        scan_network(sys.argv[2])
    if args.syn_scan:
        syn_scan(sys.argv[2])

