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

# Parse command-line flags
def parse_flag(flag, value):
    global filename
    global shuffle_option
    
    if flag == "help" or flag == "h":
        print(messages.DEBUGMSG)
    elif flag == "shuffle":
        shuffle_option = value or 'no'
    elif flag == "write":
        filename = value or 'output.pcap'
    else:
        print("Unrecognized flag. Use --help.")

# Parse command-line arguments for modifying packet fields
def parse_args(args, packet):
    if args:
        arguments = args.replace(" ", "").split(",")
        
        for argument in arguments:
            try:
                arg_x, arg_y = argument.split("=")
                
                if arg_x == "src" and Ether in packet:
                    packet[Ether].src = arg_y
                elif arg_x == "dst" and Ether in packet:
                    packet[Ether].dst = arg_y
                elif arg_x == "src" and IP in packet:
                    packet[IP].src = arg_y
                elif arg_x == "dst" and IP in packet:
                    packet[IP].dst = arg_y
                elif arg_x == "ttl" and IP in packet:
                    packet[IP].ttl = int(arg_y)
                elif arg_x == "src" and IPv6 in packet:
                    packet[IPv6].src = arg_y
                elif arg_x == "dst" and IPv6 in packet:
                    packet[IPv6].dst = arg_y
                elif arg_x == "tc" and IPv6 in packet:
                    packet[IPv6].tc = int(arg_y, 16)
                elif arg_x == "hlim" and IPv6 in packet:
                    packet[IPv6].hlim = int(arg_y)
                elif arg_x == "sport" and TCP in packet:
                    packet[TCP].sport = int(arg_y)
                elif arg_x == "dport" and TCP in packet:
                    packet[TCP].dport = int(arg_y)
                elif arg_x == "seq" and TCP in packet:
                    packet[TCP].seq = int(arg_y)
                elif arg_x == "ack" and TCP in packet:
                    packet[TCP].ack = int(arg_y)
                elif arg_x == "flags" and TCP in packet:
                    packet[TCP].flags = arg_y
                elif arg_x == "type" and ICMP in packet:
                    packet[ICMP].type = int(arg_y)
                elif arg_x == "code" and ICMP in packet:
                    packet[ICMP].code = int(arg_y)
                elif arg_x == "id" and ICMP in packet:
                    packet[ICMP].id = int(arg_y)
                elif arg_x == "seq" and ICMP in packet:
                    packet[ICMP].seq = int(arg_y)
                elif arg_x == "sport" and UDP in packet:
                    packet[UDP].sport = int(arg_y)
                elif arg_x == "dport" and UDP in packet:
                    packet[UDP].dport = int(arg_y)
                elif arg_x == "len" and UDP in packet:
                    packet[UDP].len = 8 + len(packet[UDP].payload)
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
    
    if packet_type == 'ethernet':
        packet = Ether() / Raw()
    elif packet_type == 'ipv4':
        packet = Ether() / IP()
    elif packet_type == 'ethernet ipv4':
        packet = Ether() / IP()
    elif packet_type == 'ipv6':
        packet = Ether() / IPv6()
    elif packet_type == 'ethernet ipv6':
        packet = Ether() / IPv6()
    elif packet_type == 'tcp':
        packet = Ether() / IP() / TCP()
    elif packet_type == 'ipv4 tcp':
        packet = Ether() / IP() / TCP()
    elif packet_type == 'ipv6 tcp':
        packet = Ether() / IPv6() / TCP()
    elif packet_type == 'udp':
        packet = Ether() / IP() / UDP()
    elif packet_type == 'ipv4 udp':
        packet = Ether() / IP() / UDP()
    elif packet_type == 'ipv6 udp':
        packet = Ether() / IPv6() / UDP()
    elif packet_type == 'icmp':
        packet = Ether() / IP() / ICMP()
    elif packet_type == 'ipv4 icmp':
        packet = Ether() / IP() / ICMP()
    elif packet_type == 'ipv6 icmp':
        packet = Ether() / IPv6() / ICMP()
    elif packet_type == 'ipv6 ipv4':
        packet = Ether() / IPv6() / IP()
    elif packet_type == 'ipv6 ipv6':
        packet = Ether() / IPv6() / IPv6()
    else:
        print("Invalid packet type.")
        return None
    
    for i in range(int(num)):
        packet.src = "00:11:22:33:44:55"
        packet.dst = "66:77:88:99:AA:BB"
        packet = parse_args(args, packet)
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
                
                if arguments[i].isdigit() or arguments[i].startswith('-'):
                    i -= 1
                    break
            
            parse_packets(packet_info)
        else:
            print('arg not parsed:', argument)
        
        i += 1

if __name__ == "__main__":
    if len(sys.argv) > 1:
        arguments = parse_arguments(*sys.argv[1:])
        parse_syntax(arguments)
        packet_processor()
    else:
        print(messages.DEBUGMSG)
