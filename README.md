# SailorCapy
## v0.11a

SailorCapy is a Python program for generating network packets using the Scapy library. It allows you to customize and create packets based on different protocols and parameters. This README provides example use cases to demonstrate how to use SailorCapy effectively.

## Prerequisites

Before using SailorCapy, make sure you have the following prerequisites installed:

- Python: [Download and install Python](https://www.python.org/downloads/) on your system.
- Scapy: Install Scapy using the following command:
  ```
  pip install scapy
  ```

## Installation

1. Clone the SailorCapy repository.
2. Install the required dependencies using `pip install -r requirements.txt`.

## Usage

Run SailorCapy with the following command:

```
python sailorcapy.py [arguments]
```

## Examples

 1. Generate 20 VLAN IPv4 packets followed by 30 IPv6 packets, write to "output.pcap" and shuffle the packets:
    ```
    python sailorcapy.py 20 vlan ipv4 30 ipv6 --write=output.pcap --shuffle=yes
    ```

 2. Generate 4 IPv4 packets followed by 4 IPv6 packets, write to "output.pcap" and do not shuffle the packets:
    ```
    python sailorcapy.py 4 ipv4 4 ipv6 --write=output.pcap --shuffle=no
    ```

 3. Generate 4 Ethernet packets followed by 4 IPv6 packets, write to "output.pcap" and shuffle the packets:
    ```
    python sailorcapy.py 4 ethernet 4 ipv6 --write=output.pcap --shuffle=yes
    ```

 4. Generate 4 Ethernet packets followed by 4 IPv4 packets, and then 4 Ethernet packets followed by 4 IPv6 packets, write to "output.pcap" and do not shuffle the packets:
    ```
    python sailorcapy.py 4 ethernet ipv4 4 ethernet ipv6 --write=output.pcap --shuffle=no
    ```

 5. Generate 4 TCP packets, 4 UDP packets, and 4 IPv4 packets, write to "output.pcap" and shuffle the packets:
    ```
    python sailorcapy.py 4 tcp 4 udp 4 ipv4 --write=output.pcap --shuffle=yes
    ```

 6. Generate 4 IPv4 packets with TTL set to 5, followed by 4 Ethernet packets, 4 IPv4 packets, and 4 Ethernet packets followed by 4 IPv6 packets. Write to "output.pcap" and do not shuffle the packets:
    ```
    python sailorcapy.py 4 ipv4 [ttl=5] 4 ethernet ipv4 4 ethernet ipv6 --write=output.pcap --shuffle=no
    ```

 7. Generate 10 IPv4 packets with a TTL of 64, write to "output.pcap" and shuffle the packets:
    ```
    python sailorcapy.py 10 ipv4 [ttl=64] --write=output.pcap --shuffle=yes
    ```

 8. Generate 5 IPv6 packets with a Hop Limit of 128, write to "output.pcap" and do not shuffle the packets:
    ```
    python sailorcapy.py 5 ipv6 [hlim=128] --write=output.pcap --shuffle=no
    ```

 9. Generate 6 TCP packets with a source port of 8080, write to "output.pcap" and shuffle the packets:
    ```
    python sailorcapy.py 6 tcp [sport=8080] --write=output.pcap --shuffle=yes
    ```

 10. Generate 4 UDP packets with a destination port of 5000, write to "output.pcap" and do not shuffle the packets:
     ```
     python sailorcapy.py 4 udp [dport=5000] --write=output.pcap --shuffle=no
     ```

 11. Generate 3 IPv4 packets with a TTL of 32, followed by 3 IPv6 packets with a Hop Limit of 64, write to "output.pcap" and shuffle the packets:
     ```
     python sailorcapy.py 3 ipv4 [ttl=32] 3 ipv6 [hlim=64] --write=output.pcap --shuffle=yes
     ```

 12. Generate 2 TCP packets with a source port of 8888, followed by 2 UDP packets with a destination port of 1234, and then 2 IPv4 packets with a TTL of 128. Write to "output.pcap" and do not shuffle the packets:
     ```
     python sailorcapy.py 2 tcp [sport=8888] 2 udp [dport=1234] 2 ipv4 [ttl=128] --write=output.pcap --shuffle=no
     ```

  13. Generate packets from the input configuration file input.txt:
  ```
  python sailorcapy.py input.txt
  ```

Feel free to adjust the quantities, packet types, and modify the field values in the square brackets to create various packet generation scenarios.

---

To prioritize examples using --size, here are modified versions of examples 1 and 2:

   14. Generate 20 VLAN IPv4 packets followed by 30 IPv6 packets, write to "output.pcap" and shuffle the packets:
   ```
   python sailorcapy.py --size=512 vlan ipv4 ipv6 --write=output.pcap --shuffle=yes
   ```
   15. Generate 4 IPv4 packets followed by 4 IPv6 packets, write to "output.pcap" and do not shuffle the packets:
   ```
   python sailorcapy.py --size=1024 ipv4 ipv6 --write=output.pcap --shuffle=no
   ```
---

The default behavior is to populate the fields with random data, to manually modify behavior:

   16. Generate 20 VLAN IPv4 packets followed by 30 IPv6 packets, write to "output.pcap" and randomize the data in the packets:
   ```
   python sailorcapy.py --size=512 vlan ipv4 ipv6 --write=output.pcap --random=yes
   ```
   17. Generate 4 IPv4 packets followed by 4 IPv6 packets, write to "output.pcap" and do not randomize:
   ```
   python sailorcapy.py --size=1024 ipv4 ipv6 --write=output.pcap --random=no
   ```
---

Experimental: to generate SRv6 packets:

   18. Generate 20 SRv6 packets:
   ```
   python sailorcapy.py --size=512 srv6 --random=yes
   ```
---

Make sure to replace `[arguments]` in the usage section with the desired arguments based on the provided examples.

Enjoy using SailorCapy for generating network packets!

## License 

This program is licensed under the [MIT License](https://opensource.org/licenses/MIT).