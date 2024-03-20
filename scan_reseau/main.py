import scapy.all as scapy
from collections import Counter



def print_info(packet):
    print(packet.summary())


def analyse_packet(packets):
    ip_addresses = []
    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_addresses.append(packet[scapy.IP].src)

    ip_counter = Counter(ip_addresses)
    print(ip_counter)



if __name__ == "__main__":
    # pour lister les interfaces réseau
    print(scapy.get_if_list())

    interface_name = "nom_de_l'interface"

    #sniff permet d'écouter notre interface réseau
    p = scapy.sniff(count=1, iface=interface_name, prn=print_info)
    # en rajoutant le iface on lui précisément sur quelle interface écouter

    # le show va permettre de regarder en détail un paquet.
    # p va contenir un ensemble de paquets donc on met 0 pour s'intéresser au premier
    p[0].show()

    # summary va être plus bref et renvoyer des informations moins détaillées sur le paquet
    print(p[0].summary())
    #là cela va nous résumer l'ensemble des paquets
    print(p.summary())
    print(p)

# on peut intégrer des fichiers wireshark
    
    p = scapy.rdpcap("./nom du fichier wireshark")
    analyse_packet(p)