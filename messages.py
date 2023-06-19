DEBUGMSG = '''
Usage: sailorcopy [ -<flag> [<val>] | --<name>[{=| }<val>] ]... <packet_info>...

<packet_info> ::= <num> <packet_type> [<arg1>=<value1>] [<arg2>=<value2>] ...

<num> ::= an integer specifying the number of packets to generate
<packet_type> ::= "ethernet" | "ipv4" | "ipv6" | "tcp" | "udp" | "icmp" | "ipv6 ipv4" | "ipv6 ipv6"...
<arg1>, <arg2>, ... ::= optional arguments specific to the packet type


--output=str Set output filename (default: "output.pcap")
--shuffle=str Shuffle packets before writing ("yes" or "no", default: "no")
-h, --help Display usage information and exit

Options are specified by doubled hyphens.

Sailorcapy is a tool for processing network packets and generating pcap files.

Please send bug reports to: your-email@example.com
'''