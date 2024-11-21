# DynasFirewall

A powerful and customizable firewall implemented in C, leveraging the Netfilter framework. This project enables dynamic packet filtering based on IP, port, and protocol, with support for rule management via configuration files.

---

## Features

- **Dynamic rule management** through a configuration file (`firewall_rules.conf`).
- **Packet filtering** based on IPs, ports, and protocols (TCP, UDP, ICMP).
- **Logging** for blocked packets to facilitate audits.
- Built on the **Netfilter** framework for high performance on Linux systems.

---

## Dependencies

To build and run DynasFirewall, you need the following dependencies installed on your Linux system:

1. Install the C Compiler (GCC):
   ```bash
   sudo apt-get install build-essential
   ```

2. Install the Netfilter Libraries:
   ```bash
   sudo apt-get install libnetfilter-queue-dev libnfnetlink-dev
   ```

3. Install Development Libraries:
   ```bash
   sudo apt-get install libc-dev
   ```

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dynasmon/dynasfirewall.git
   cd dynasfirewall
   ```

2. Compile the source code:
   ```bash
   gcc -o firewall dynas_firewall.c -lnetfilter_queue
   ```

3. Create or edit the configuration file:
   - File: `firewall_rules.conf`
   - Format:
     ```
     src_ip dst_ip src_port dst_port protocol action
     ```
   - Example:
     ```
     192.168.1.100 * 0 0 TCP 0
     * 10.0.0.1 0 22 UDP 0
     * * 0 0 ICMP 1
     ```

4. Add `iptables` rules to direct traffic to the firewall:
   ```bash
   sudo iptables -A INPUT -j NFQUEUE --queue-num 0
   sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
   ```

5. Run the firewall:
   ```bash
   sudo ./firewall
   ```

---

## Usage

- **Editing Rules:** Modify the `firewall_rules.conf` file to update packet filtering rules dynamically.
- **Monitoring Logs:** View logs of blocked packets:
  ```bash
  tail -f /var/log/firewall.log
  ```

---

## Troubleshooting

1. **Missing `NF_DROP` or `NF_ACCEPT`:**
   - Include `<linux/netfilter.h>` in the code.
   - Define missing macros if necessary:
     ```c
     #ifndef NF_DROP
     #define NF_DROP 0
     #endif

     #ifndef NF_ACCEPT
     #define NF_ACCEPT 1
     #endif
     ```

2. **Netfilter Queue Issues:**
   - Ensure required modules are loaded:
     ```bash
     sudo modprobe nf_conntrack
     sudo modprobe nfnetlink_queue
     ```

3. **Iptables Configuration:**
   - Verify that iptables rules are applied correctly:
     ```bash
     sudo iptables -L -v
     ```

---

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
