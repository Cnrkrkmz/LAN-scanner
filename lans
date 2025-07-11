import os
from scapy.all import ARP, Ether, srp
from scapy.all import ICMP, IP, sr1
import ipaddress

ip_range = "192.168.1.0/24"

def icmp_ping(ip):
    pkt = IP(dst=str(ip)) / ICMP()
    resp = sr1(pkt, timeout=1, verbose=0)
    return resp is not None
active_ips = []

for ip in ipaddress.IPv4Network(ip_range).hosts():
    if icmp_ping(ip):
        print(ip)
        active_ips.append(str(ip))

print("[+] Aktif IP'ler:")
def arp_request():
    devices = []
    for ip in active_ips:
        print(ip) #for debug

        ether = Ether(dst = "ff:ff:ff:ff:ff:ff") # Broadcast address

        arp = ARP(pdst= ip) #pdst is where the arp packet should go

        packet = ether / arp #send the arp request buried inside the broadcast address as a whole packet
        result = srp(packet, timeout=2, verbose=0)[0] #srp output results in two different situations as answered and unanswered so we just get 
                                              #the first variable which is answered with [0]
                                              #and answered returns a list which all its elements are a tuple (sent, recieved)

        for sent, received in result:
            devices.append({'IP': received.psrc, 'MAC': received.hwsrc}) #psrc for ip address, hwsrc for mac address

    for device in devices:
        print(f'IP: {device["IP"]} \nMAC: {device["MAC"]}')

arp_request()
