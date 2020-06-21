# Sniffing concepts
- Packet sniffing is a process of monitoring and capturing all data packets passing through a given network using a software application or hardware device
- Sniffer turns the NIC of a system to the promiscuous mode so that it listens to all the data transmitted on its segment
- The major difference between a hub and a switch is that a hub transmits line data to each port on the machine and has no line mapping, whereas a switch looks at the Media Access Control (MAC) address associated with each frame passing through it and sends the data to the required port.
-  Sniffing programs turn off the filter employed by Ethernet network interface cards (NICs) to prevent the host machine from seeing other stations’ traffic. Thus, sniffing programs can see everyone’s traffic
-  There are two basic types of Ethernet environments, and sniffers work differently in each. The two types of Ethernet environments are: 
   -  shared Ethernet
      -  a single bus connects all the hosts that compete for bandwidth
   - switched Ethernet
     -  the hosts connect with a switch instead of a hub. The switch maintains a table that tracks each computer’s MAC address and the physical port on which that MAC address is connected, and then delivers packets destined for a particular machine. 
     -   the process of putting a machine NIC into promiscuous mode to gather packets does not work
- sniffing methods
  - ARP Spoofing 
    - When a machine wants to sniff the traffic originating from another system, it can ARP spoof the gateway of the network
  - MAC flooding
- types of sniffing
  - passive
    - Compromising the physical security:
    - Using a Trojan horse
  - active
    - MAC flooding
    -  DNS poisoning 
    -  ARP poisoning 
    -  DHCP attacks
    -  Switch port stealing
    -  Spoofing attack
 - Protocols Vulnerable to Sniffing - Passwords and data are sent in clear text
   - Telnet and Rlogin
   - HTTP
   - SNMP
   - POP
   - FTP
   - IMAP
- Sniffers operate at the data link layer of the OSI model 
- HArdware Protocol analyzers
  -  It allows the attacker to see individual data bytes of each packet passing through the cable
  - A hardware protocol analyzer is a piece of equipment that captures signals without altering the traffic in a cable segment 
  - tools
    - Keysight E2960B 
- SPAN port
  - SPAN port is a port that is configured to receive a copy of every packet that passes through a switch
- Wiretapping 
  - is the process of monitoring telephone and Internet conversations by a third party
  - types
    - active
    - passive
# Sniffing Technique: MAC Attacks 
- Attackers use the MAC flooding technique to force a switch to act like hub, so that they can easily sniff the traffic.
- The CAM table stores information such as MAC addresses available on physical ports with their associated virtual LAN (VLAN) parameters
- MAc address length
  - 48 bits
    - 24 id of manufacturer
    -  24 nic specific
- when the CAM table is full
  - additional ARP request traffic flood every port on the switch
  - This will change the behavior of the switch to reset to its learning mode, broadcasting on every port similar to a hub
- Techniques
  - MAC flooding
    - MAC flooding involves flooding of CAM table with fake MAC address and IP pairs until it is full
    - The switch then acts as a hub by broadcasting packets to all machines on the network and therefore, the attackers can sniff the traffic easily
  - Switch Port Stealing
    - Switch Port Stealing sniffing technique uses MAC flooding to sniff the packets
    - Attacker floods the switch with forged gratuitous ARP packets with target MAC address as source and his/her own MAC address as destination
    - A race condition of attacker’s flooded packets and target host packets occur and thus switch has to change its MAC address binding constantly between two different ports
    - In such case if attacker is fast enough, he/she will able to direct the packets intended for the target host toward his switch port
    - Attacker now manages to steal the target host switch port and sends ARP request to stolen switch port to discover target hosts’ IP address
    - When attacker gets ARP reply, this indicates that target host’s switch port binding has been restored and attacker can now sniff the packets sent toward targeted host
- MAC attack countermesasures
  - Configuring Port Security on Cisco switch: 
    - switchport port-security 
    - switchport port-security maximum 1 vlan access 
    - switchport port-security violation restrict 
    - switchport port-security aging time 2 
    - switchport port-security aging type inactivity 
    - snmp-server enable traps port-security trap-rate 5
  # Sniffing Technique: DHCP Attacks
  - techniques
    - DHCP starvation 
      - an attacker floods the DHCP server by sending a large number of DHCP requests and uses all of the available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to Denial-of-Service (DoS) attacks.
    - Rogue DHCP Server Attack 
      - Attacker sets rogue DHCP server in the network and responds to DHCP requests with bogus IP addresses resulting in compromised network access
      - This attack works in conjunction with the DHCP starvation attack; attacker sends TCP/IP setting to the user after knocking him/her out from the genuine DHCP server
  - DHCP attack countermeasures
    - note: All ports in the VLAN are untrusted by default. 
    - Enable port security 
      -  limits the maximum number of MAC addresses on the switch port. When the limit is exceeded, the switch drops subsequent MAC address requests (packets) coming from external sources which safeguard the server against a DHCP starvation attack.
    - DHCP snooping
      -  ip dhcp snooping vlan 4,104 
         -  Enable or disable DHCP snooping on one or more VLANs.
      -   no ip dhcp snooping information option
            - To disable the insertion and the removal of the option-82 field, use the no IP dhcp snooping information option in global configuration command. To configure an aggregation, switch to drop incoming DHCP snooping packets with option-82 information from an edge switch, use the no IP dhcp snooping information option allow-untrusted global configuration command.
      - ip dhcp snooping 
        - Enable DHCP snooping option globally.

# Sniffing Technique: ARP Poisoning

- countermeausres
  -  Dynamic ARP Inspection 
     -  DAI is a security feature that validates ARP packets in a network
     -  to validate the ARP packet, the DAI performs IP address-to-MAC address binding inspection stored in the DHCP snooping database before forwarding the packet to its destination
     -  Implementation of cryptographic protocols as HTTP Secure (HTTPS), Secure Shell (SSH), Transport Layer Security (TLS), and various other networking cryptographic protocols prevents against ARP spoofing attack by encrypting data before transmission and authenticating it after it is received
# Sniffing Technique: Spoofing Attacks 
### MAC Spoofing/Duplicating
- MAC duplicating refers to spoofing a MAC address with the MAC address of a legitimate user on the network
##  IRDP Spoofing
- ICMP Router Discovery Protocol (IRDP) is a routing protocol that allows host to discover the IP addresses of active routers on their subnet by listening to router advertisement and soliciting messages on their network
- Attacker sends spoofed IRDP router advertisement message to the host on the subnet, causing it to change its default router to whatever the attacker chooses
- This attack allows attacker to sniff the traffic and collect the valuable information from the packets 
- Attackers can use IRDP spoofing to launch man-in-the-middle, denial-of-service, and passive sniffing attacks

### countermeasures
-  DHCP Snooping Binding Table
   -  The DHCP snooping process filters untrusted DHCP messages and helps to build and bind a DHCP binding table
-  Dynamic ARP Inspection,
   -  The system checks the IP to MAC address binding for each ARP packet in a network. While performing a Dynamic ARP inspection, the system will automatically drop invalid IP to MAC address bindings
-  IP Source Guard
   -  IP Source Guard is a security feature in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database.
   -  Use of AAA (Authentication, Authorization and Accounting) server mechanism in order to filter MAC addresses subsequently

# Sniffing Technique: DNS Poisoning
- DNS poisoning is a technique that tricks a DNS server into believing that it has received authentic information when, in reality, it has not received any
- It results in substitution of a false IP address at the DNS level where web addresses are converted into numeric IP addresses
- It allows attacker to replace IP address entries for a target site on a given DNS server with IP address of the server he/she controls
- Attacker can create fake DNS entries for the server (containing malicious content) with names similar to that of the target server
- DNS poisoning is possible using the following techniques: 
  -  Intranet DNS Spoofing 
     -  For this technique, the system must be connected to the local area network (LAN) and be able to sniff packets 
     -   It works well against switches with ARP Poison Routing
  -  Internet DNS Spoofing 
     -  Internet DNS Spoofing, attacker infects targets machine with a Trojan and changes her DNS IP address to that of the attacker’s

  -  Proxy Server DNS Poisoning 
     -  Attacker sends a Trojan to targets machine that changes her proxy server settings in Internet Explorer to that of the attacker’s and redirects to fake website

  -  DNS Cache Poisoning
     -  DNS cache poisoning refers to altering or adding forged DNS records into the DNS resolver cache so that a DNS query is redirected to a malicious site 
     -  If the DNS resolver cannot validate that the DNS responses have been received from an authoritative source, it will cache the incorrect entries locally, and serve them to users who make the similar request
- countermeasures
  -  Implement Domain Name System Security Extension (DNSSEC)
  -   Use Secure Socket Layer (SSL) for securing the traffic 
  -   Resolve all DNS queries to local DNS server 
  -   Block DNS requests being sent to external servers 

# Sniffing Detection Techniques
- Promiscuous Mode
  -  You will need to check which machines are running in the promiscuous mode 
  -  Promiscuous mode allows a network device to intercept and read each network packet that arrives in its entirety
- IDS
  - Run IDS and notice if the MAC address of certain machines has changed (Example: router’s MAC address) IDS can alert the administrator about suspicious activities
- Network tools
  - Run network tools such as Capsa Network Analyzer to monitor the network for detecting strange packets 
  - Enables to collect, consolidate, centralize, and analyze traffic data across different network resources and technologies
- Ping method
  - Sends a ping request to the suspect machine with its IP address and incorrect MAC address. The Ethernet adapter rejects it, as the MAC address does not match, whereas the suspect machine running the sniffer responds to it as it does not reject packets with a different MAC address
- DNS method
  - The reverse DNS lookup is the opposite of the DNS lookup method. Sniffers using reverse DNS lookup increase network traffic. This increase in network traffic can be an indication of the presence of a sniffer on the network
- ARP method
  - Only a machine in promiscuous mode (machine C) caches the ARP information (IP and MAC address mapping)
  - A machine in promiscuous mode responds to the ping message as it has correct information about the host sending the ping request in its cache; rest of the machines will send ARP probe to identify the source of ping request











