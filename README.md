DynasFirewall
A powerful and customizable firewall implemented in C, leveraging the Netfilter framework. This project enables dynamic packet filtering based on IP, port, and protocol, with support for rule management via configuration files.

Features
Dynamic rule management through a configuration file (firewall_rules.conf).
Packet filtering based on IPs, ports, and protocols (TCP, UDP, ICMP).
Logging for blocked packets to facilitate audits.
Built on the Netfilter framework for high performance on Linux systems.
Dependencies
To build and run DynasFirewall, you need the following dependencies installed on your Linux system:

C Compiler (GCC): sudo apt-get install build-essential

Netfilter Libraries:

libnetfilter_queue: For interacting with Netfilter queues.
libnfnetlink: For communication between the kernel and user space. sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev
Development Libraries:

libc-dev: Provides essential headers for system-level programming. sudo apt-get install libc-dev
Installation
Clone the repository: git clone https://github.com/dynasmon/dynasfirewall.git cd dynasfirewall

Compile the source code: gcc -o firewall dynas_firewall.c -lnetfilter_queue

Create or edit the configuration file:

File: firewall_rules.conf
Format: src_ip dst_ip src_port dst_port protocol action Example: 192.168.1.100 * 0 0 TCP 0
10.0.0.1 0 22 UDP 0
0 0 ICMP 1
Add iptables rules to direct traffic to the firewall: sudo iptables -A INPUT -j NFQUEUE --queue-num 0 sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0

Run the firewall: sudo ./firewall

Usage
Editing Rules: Modify the firewall_rules.conf file to update packet filtering rules dynamically.
Monitoring Logs: View logs of blocked packets: tail -f /var/log/firewall.log
Troubleshooting
Missing NF_DROP or NF_ACCEPT:

Include <linux/netfilter.h> in the code.
Define missing macros if necessary: #ifndef NF_DROP #define NF_DROP 0 #endif #ifndef NF_ACCEPT #define NF_ACCEPT 1 #endif
Netfilter Queue Issues:

Ensure required modules are loaded: sudo modprobe nf_conntrack sudo modprobe nfnetlink_queue
Iptables Configuration:

Verify that iptables rules are applied correctly: sudo iptables -L -v
License
This project is distributed under the MIT License. See the LICENSE file for details.
