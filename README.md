# Simple LAN scanner 

- This is a small project I built to scan my local network and find out which devices are connected. 
- It uses Python and Scapy to send ARP requests and shows the IP and MAC addresses of devices that respond.

# What It Does

- Sends ARP broadcast requests to the entire subnet (like 192.168.1.0/24 as im using a class ip)
- Collects responses from devices and prints their IP and MAC addresses
- You can also combine it with ICMP (ping) to wake up some devices that don't reply to ARP alone

# Limitations

- Some devices (like phones) might not respond to ARP unless they’re actively using the network
- ICMP (ping) helps, but not always
- Tested on macOS and Kali Linux. Probably won’t work on Windows as-is.


- ## Note

- Because of some devices might not respond to ARP and ICMP i have implemented an arp-cache reader. When we ping devices with ICMP we get their MAC addresses in OS level, this way we dont engage with any security issues and even if the comminucated devices dont show up on the output of the code they will still appear in arp cache

# Example Output

IP: 192.168.1.1
MAC: 90:9a:4a:a3:f0:86
IP: 192.168.1.108
MAC: 2a:bb:c1:80:4a:9f

- It should be run as "sudo"
