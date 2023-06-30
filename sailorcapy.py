"""
SailorCapy

This program generates packets based on user input and writes them to a pcap file.
It supports various packet types such as Ethernet, IPv4, IPv6, TCP, UDP, and ICMP.

# Author: Mohammad Firas Sada
# Email: mhd.firas.sada@gmail.com
# Date: June 19, 2023
# MIT License

"""

import sys
import messages
import re
import subprocess
from scapy.all import *
from random import shuffle

# Parse command-line arguments
def parse_arguments(*args):
    arguments = []
    
    for arg in args:
        arguments.extend(arg.split())
    
    return arguments

packets = []
filename = "output.pcap"
shuffle_option = "no"
packet_size = None
random = "yes"

# Parse command-line flags
def parse_flag(flag, value):
    global filename
    global shuffle_option
    global packet_size
    global random

    if flag == "help" or flag == "h":
        print(messages.DEBUGMSG)
    elif flag == "shuffle":
        shuffle_option = value or 'no'
    elif flag == "write":
        filename = value or 'output.pcap'
    elif flag == "size":
        packet_size = int(value) or "None"
    elif flag == "random":
        packet_size = value or 'yes'
    else:
        print("Unrecognized flag. Use --help.")

# Parse command-line arguments for modifying packet fields
def parse_args(args, packet):
    if args:
        arguments = args.replace(" ", "").split(",")
        
        for argument in arguments:
            try:
                arg_x, arg_y = argument.split("=")
                
                if arg_x == "len" and UDP in packet:
                    packet[UDP].len = 8 + len(packet[UDP].payload)
                elif arg_x == "dport" and UDP in packet:
                    packet[UDP].dport = int(arg_y)
                elif arg_x == "sport" and UDP in packet:
                    packet[UDP].sport = int(arg_y)
                elif arg_x == "seq" and ICMP in packet:
                    packet[ICMP].seq = int(arg_y)
                elif arg_x == "id" and ICMP in packet:
                    packet[ICMP].id = int(arg_y)
                elif arg_x == "code" and ICMP in packet:
                    packet[ICMP].code = int(arg_y)
                elif arg_x == "type" and ICMP in packet:
                    packet[ICMP].type = int(arg_y)
                elif arg_x == "flags" and TCP in packet:
                    packet[TCP].flags = arg_y
                elif arg_x == "ack" and TCP in packet:
                    packet[TCP].ack = int(arg_y)
                elif arg_x == "seq" and TCP in packet:
                    packet[TCP].seq = int(arg_y)
                elif arg_x == "dport" and TCP in packet:
                    packet[TCP].dport = int(arg_y)
                elif arg_x == "sport" and TCP in packet:
                    packet[TCP].sport = int(arg_y)
                elif arg_x == "hlim" and IPv6 in packet:
                    packet[IPv6].hlim = int(arg_y)
                elif arg_x == "tc" and IPv6 in packet:
                    packet[IPv6].tc = int(arg_y, 16)
                elif arg_x == "dst" and IPv6 in packet:
                    packet[IPv6].dst = arg_y
                elif arg_x == "src" and IPv6 in packet:
                    packet[IPv6].src = arg_y
                elif arg_x == "ttl" and IP in packet:
                    packet[IP].ttl = int(arg_y)
                elif arg_x == "dst" and IP in packet:
                    packet[IP].dst = arg_y
                elif arg_x == "src" and IP in packet:
                    packet[IP].src = arg_y
                elif arg_x == "dst" and Ether in packet:
                    packet[Ether].dst = arg_y
                elif arg_x == "src" and Ether in packet:
                    packet[Ether].src = arg_y

                else:
                    print("Invalid field or protocol.")
            except ValueError:
                print("Invalid argument format:", argument)
    
    return packet

# Parse packet information and create packet objects
def parse_packets(packet_info):
    num = packet_info[0]
    args = []
    
    if len(packet_info) < 2:
        print(messages.DEBUGMSG)
        sys.exit()
    
    packet_info = packet_info[1:]
    
    if packet_info[-1].startswith('['):
        args = packet_info[-1][1:][:-1]
        packet_info = packet_info[:-1]
    
    packet_type = ' '.join(packet_info)
    
    if random == "no":
        eth_src = "00:11:22:33:44:55"  # Example Ethernet source MAC address
        eth_dst = "AA:BB:CC:DD:EE:FF"  # Example Ethernet destination MAC address
        ip_src = "192.168.0.1"  # Example source IP address
        ip_dst = "10.0.0.1"  # Example destination IP address
        tcp_sport = 1234  # Example TCP source port
        tcp_dport = 80  # Example TCP destination port
        udp_sport = 5678  # Example UDP source port
        udp_dport = 53  # Example UDP destination port
        icmp_type = 8  # Example ICMP type (Echo Request)
        icmp_code = 0  # Example ICMP code
        vlan_id = 100  # Example VLAN ID
    else:
        # Generate random data for t``he fields
        eth_src = RandMAC()
        eth_dst = RandMAC()
        ip_src = RandIP()
        ip_dst = RandIP()
        tcp_sport = RandNum(0, 65535)
        tcp_dport = RandNum(0, 65535)
        udp_sport = RandNum(0, 65535)
        udp_dport = RandNum(0, 65535)
        icmp_type = RandNum(0, 255)
        icmp_code = RandNum(0, 255)
        vlan_id = RandNum(1, 4094)


    # Create the packet with random data
    if packet_type == 'ethernet':
        packet = Ether(src=eth_src, dst=eth_dst) / Raw(load=RandString(10))
    elif packet_type == 'ipv4':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst)
    elif packet_type == 'ethernet ipv4':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst)
    elif packet_type == 'ipv6':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6())
    elif packet_type == 'ethernet ipv6':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6())
    elif packet_type == 'tcp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / TCP(sport=tcp_sport, dport=tcp_dport)
    elif packet_type == 'ipv4 tcp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / TCP(sport=tcp_sport, dport=tcp_dport)
    elif packet_type == 'ipv6 tcp':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6()) / TCP(sport=tcp_sport, dport=tcp_dport)
    elif packet_type == 'udp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=udp_sport, dport=udp_dport)
    elif packet_type == 'ipv4 udp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / UDP(sport=udp_sport, dport=udp_dport)
    elif packet_type == 'ipv6 udp':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6()) / UDP(sport=udp_sport, dport=udp_dport)
    elif packet_type == 'icmp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / ICMP(type=icmp_type, code=icmp_code)
    elif packet_type == 'ipv4 icmp':
        packet = Ether(src=eth_src, dst=eth_dst) / IP(src=ip_src, dst=ip_dst) / ICMP(type=icmp_type, code=icmp_code)
    elif packet_type == 'ipv6 icmp':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6()) / ICMPv6EchoRequest()
    elif packet_type == 'ipv6 ipv4':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6()) / IP(src=ip_src, dst=ip_dst)
    elif packet_type == 'ipv6 ipv6':
        packet = Ether(src=eth_src, dst=eth_dst) / IPv6(src=RandIP6(), dst=RandIP6()) / IPv6(src=RandIP6(), dst=RandIP6())
    elif packet_type == 'vlan ipv4':
        packet = Ether(src=eth_src, dst=eth_dst) / Dot1Q(vlan=vlan_id) / IP(src=ip_src, dst=ip_dst)
    elif packet_type == 'vlan ipv6':
        packet = Ether(src=eth_src, dst=eth_dst) / Dot1Q(vlan=vlan_id) / IPv6(src=RandIP6(), dst=RandIP6())
    elif packet_type in ['ipv6 srv6', 'srv6', 'ethernet srv6', 'ethernet ipv6 srv6']:
        ether = Ether(src=eth_src, dst=eth_dst)
        ipv6 = IPv6(dst="2001:db8::1", src="2001:db8::2")
        srh = IPv6ExtHdrSegmentRouting()
        srh.addresses = ["2001:db8::3", "2001:db8::4", "2001:db8::5"]  # Example segments
        icmpv6 = ICMPv6EchoRequest(data=Raw("Hello, SRv6!"))
        packet = ether / ipv6 / srh / icmpv6

    else:
        print("Invalid packet type.")
        return None
    
    for i in range(int(num)):
        packet = parse_args(args, packet)
        if packet_size is not None:
            current_size = len(packet)
            if current_size < packet_size:
                padding = b'\x00' * (packet_size - current_size)
                packet = packet / Raw(load=padding)
            elif current_size > packet_size:
                packet[Raw].load = packet[Raw].load[:packet_size - current_size]
        packets.append(packet)

# Process packets and write them to a pcap file
def packet_processor():
    if packets:
        if shuffle_option == "yes":
            shuffle(packets)
        wrpcap(filename, packets)

# Parse command-line syntax
def parse_syntax(arguments):
    i = 0
    if len(arguments) == 1:
        with open(arguments[0], 'r') as file:
            for line in file.read().splitlines():
                args = line.split(" ")
                args = ['python3', 'sailorcapy.py'] + args
                subprocess.call(args)
                sys.exit()
    arguments = sorted(arguments, key=lambda x: not x.startswith("--"))
    while i < len(arguments):
        argument = arguments[i]
        
        if argument.startswith('--'):
            match = re.match(r'--(\w+)(?:=(.*))?', argument)
            
            if match:
                flag = match.group(1)
                value = match.group(2)
                parse_flag(flag, value)
            else:
                print(messages.DEBUGMSG)
        elif argument.startswith('-'):
            match = re.match(r'-([a-zA-Z])(?:\s+(\S+))?', argument)
            
            if match:
                flag = match.group(1)
                value = match.group(2)
                parse_flag(flag, value)
            else:
                print(messages.DEBUGMSG)
        elif argument.isdigit():
            packet_info = []
            
            while i < len(arguments):
                packet_info.append(arguments[i])
                i += 1
                
                if i == len(arguments) or arguments[i].isdigit() or arguments[i].startswith('-'):
                    i -= 1
                    break
            
            parse_packets(packet_info)
        else:
            print('arg not parsed:', argument)
        
        i += 1


def main(args):
    if len(args) > 1:
        arguments = parse_arguments(*args[1:])
        parse_syntax(arguments)
        packet_processor()
    else:
        print(messages.DEBUGMSG)

if __name__ == "__main__":
    main(sys.argv)