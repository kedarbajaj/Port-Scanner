import os
import sys
import socket

host=input("\n[+] Enter the IP address of the target: ")
ip = socket.gethostbyname(host)

print("\n[+] Scanning the target...")
scan = os.system("nmap -T4 -A -v "+ ip)

print("\n[+] Scan results:")
os.system("nmap -T4 -A -v -oN "+ ip + ".txt" + ip)
print("\n[+] Scan results saved to "+ ip + ".txt")