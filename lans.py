import concurrent
from scapy.all import ARP, Ether, srp
from scapy.all import ICMP, IP, sr1
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # suppress warnings caused by not knowing mac address

ip_range = "192.168.1.0/24"

def icmp_ping(ip):
    pkt = IP(dst=str(ip)) / ICMP()
    resp = sr1(pkt, timeout=2, verbose=0)
    if resp:
        return str(ip)  # return IP address
    return None

active_ips = []

def scan_network():
    network = ipaddress.IPv4Network(ip_range)
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor: #implemented thread pool because it took so long to ping all 254 ip addresses
        futures = {executor.submit(icmp_ping, ip): ip for ip in network.hosts()} # future dictionary
        for future in concurrent.futures.as_completed(futures): #read the future dictionary
            result = future.result()
            if result:
                active_ips.append(result)
    for ip in active_ips:
        print(ip)
devices = []

def broadcast_arp():

    arp = ARP(pdst=ip_range) # arp packet sent by
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp #send the arp request buried inside the broadcast address as a whole packet
    result = srp(packet, timeout=2, verbose=0)[0] #srp output results in two different situations as answered and unanswered so we just get 
                                              #the first variable which is answered with [0]
                                              #and answered returns a list which all its elements are a tuple (sent, recieved)

    for sent, received in result:
            devices.append({'IP': received.psrc, 'MAC': received.hwsrc}) #psrc for ip address, hwsrc for mac address

    for device in devices:
        print(f'IP: {device["IP"]} \nMAC: {device["MAC"]}')


    
print("Active IP Addresses: ")
scan_network()
print("MAC addresses associated with IP")
broadcast_arp()