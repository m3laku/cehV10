- network scanning: search for an entry point into the target system. It should be noted that the scanning itself is not the actual intrusion, but an extended form of reconnaissance in which the attacker learns more about his/her target, including information about operating systems, services, and any configuration lapses. The information gleaned from this reconnaissance helps the attacker select strategies for the attack on the target system or network. 

# Network scanning concepts 
- Network scanning refers to a set of procedures used for identifying hosts, ports, and services in a network
- types of scanning
    -   port scanning:
        - Lists the open ports and services. Port scanning is the process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in. Port scanning involves connecting to or probing TCP and UDP ports on the target system to determine if the services are running or are in a listening state. The listening state provides information about the operating system and the application currently in use. Sometimes, active services that are listening may allow unauthorized user access to misconfigure systems or to run software with vulnerabilities
    - network scanning:
        -  Lists IP addresses
    - Vulnerability Scanning:
        - Shows the presence of known weaknesses
        - A vulnerability scanner consists of a scanning engine and a catalog
- packet crafting tools:
    - colasoft
        - three view:
            - packet list
            - hex editor
            - decode ditor
- scanning ipv6 addresses:
    - less feasable
    - Attackers need to harvest IPv6 addresses from network traffic, recorded logs, or Received from: and other header lines in the archived email or Usenet news messages
    - offers a large number of hosts in a subnet. Once an attacker is able to compromise one host in the subnet, he or she can probe the "all hosts“ and link local multicast address
    - number of scanning tools do not support ping sweeps on IPv6 networks. 

# Scanning Tools

## nmap

- Network administrators can use Nmap for network inventory, managing service upgrade schedules, and monitoring host or service uptime
- Attacker uses Nmap to extract information such as live hosts on the network, services (application name and version), type of packet filters/firewalls, operating systems, and OS versions

## HPing
- Command line network scanning and packet crafting tool for the TCP/IP protocol
- sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols
- has a Traceroute mode which enables you to send files between covert channels
- features:
    - It determines whether the host is up even when the host blocks ICMP packets. - It aids advanced port scanning and test net performance using different protocols, packet sizes, TOS, and fragmentation.
    - Manual path MTU discovery 
    - Firewalk-like usage allows discovery of open ports behind firewalls. 
    - Remote OS fingerprinting and TCP/IP stack auditing
- ICMP Scanning:

    -   A ping sweep or Internet Control Message Protocol (ICMP) scanning is a process of sending an ICMP request or ping to all hosts on the network to determine which one is up. 
    - The operating system, router, switch, internet-protocol-based devices use this protocol via the ping command to Echo request and Echo response as a connectivity tester between different hosts
- ACK Scanning on Port 80 
    - You can use this scan technique to probe for the existence of a firewall and its rule sets. Simple packet filtering allows you to establish a connection (packets with the ACKbitset), whereas a sophisticated stateful firewall does not allow you to establish a connection.

### HPing commands

- PAGE 288!!!
- ICMP Ping: hping3 -1 10.0.0.25
- ACK scan on port 80:  
    - hping3 –A 10.0.0.25 –p 80
    - perform this scan when a host does not respond to a ping request.
    - If it finds a live host and an open port, it returns an RST response
- UDP scan on port 80:
    - hping3 -2 10.0.0.25 –p 80 
    -  It returns an ICMP port unreachable message if it finds the port closed, and does not respond with a message if the port is open
-  Collecting Initial Sequence Number:
    - hping3 192.168.1.103 -Q -p 139 –s 
- Firewalls and Time Stamps:
    -  hping3 -S 72.14.207.99 -p 80 --tcp-timestamp 
    -  Many firewalls drop those TCP packets that do not have TCP Timestamp option set. By adding the --tcp-timestamp argument in the command line, you can enable TCP timestamp option in Hping
- SYN scan on port 50-60:
    - hping3 -8 50-60 –S 10.0.0.25 –V
- FIN, PUSH and URG scan on port 80:
    - hping3 –F –P –U 10.0.0.25 –p 80
    - If port 80 is open on the target, you will not receive a response. If the port is closed, Hping will return an RST response
- Scan entire subnet for live host:
    - hping3 -1 10.0.1.x --rand-dest –I eth0 
    - The hosts whose ports are open will respond with an ICMP-reply
- Intercept all traffic containing HTTP signature:
    - hping3 -9 HTTP –I eth0
- SYN flooding a victim:
    - hping3 -S 192.168.1.1 -a 192.168.1.254 -p 22 --flood

##  NetScanTools Pro
- investigation tool that allows you to troubleshoot, monitor, discover, and detect devices on your network
-  combines many network tools and utilities categorized by their functions, such as active, passive, DNS, and local computer
- automates the processes

## Scanning tools for mobile
- IP Scanner
- fing


# Scanning techniques
-  Administrators often use port scanning techniques to verify security policies of their networks, whereas attackers use them to identify running services on a host with the intent of compromising the network

### ICMP Scanning - Checking for Live Systems
- If the host is alive, it will return an ICMP ECHO reply 
- This scan is useful for locating active devices or determining if the ICMP is passing through a firewall
- ICMP query has both a timestamp and address mask request option
-  "ICMP query <-query-> [-B] [-f fromhost] [-d delay] [-T time] target"
    - Where, <query> is one of: 
        - -t: ICMP timestamp request (default) 
        - -m: ICMP address mask request 
        - -d: delay to sleep between packets is in microseconds 
        - -T - specifies the number of seconds to wait for a host to respond. 
### Ping Sweep - Checking for Live Systems
- a ping sweep (also known as an ICMP sweep) is a basic network scanning technique that is employed to determine which range of IP addresses map to live hosts
-ping sweep tools:
    - Angry IP Scanner

###  ICMP Echo Scanning
- ICMP echo scanning pings all the machines in the target network to discover live machines. Attackers send ICMP probes to the broadcast or network address which relays to all the host addresses in the subnet. The live systems will send ICMP echo reply message to the source of the ICMP echo probe.
- DOESNT work on windows
- ICMP echo scanning is not same as port scanning because it does not have a port abstraction

### TCP Connect / Full Open Scan 
-  one of the most reliable forms of TCP scanning
- it is easily detectable and filterable

### Stealth Scan (Half-open Scan) 
-  The Stealth scan involves resetting the TCP connection between client and server abruptly before completion of the three-way handshake signals
- Attackers use stealth scanning techniques to bypass firewall rules, logging mechanism, and hide themselves as usual under network traffic.

### Inverse TCP Flag Scanning
- Attackers send TCP probe packets with a TCP flag (FIN, URG, PSH) set or with no flags, no response implies that the port is open while RST means that the port is closed
- types:
    - A FIN probe with the FIN TCP flag set 
    - An XMAS probe with the FIN, URG, and PUSH TCP flags set 
    - A NULL probe with no TCP flags set 
    - A SYN/ACK probe
- cannot see the RST/ACK response when connected to a closed port on the target host. However, this technique is effective when used with UNIX-based operating systems.
- Advantages
    - Avoids many IDS and logging systems, highly stealthy 
- Disadvantages 
    - Needs raw access to network sockets, thus requiring super-user privileges 
    - Mostly effective against hosts using a BSD-derived TCP/IP stack (not effective against Microsoft Windows hosts, in particul

### Xmas Scan
- In Xmas scan, attackers send a TCP frame to a remote device with FIN, URG, and PUSH flags set
- FIN scan works only with OSes with RFC 793-based TCP/IP implementation
It will not work against any current version of Microsoft Windows 
-use this port scanning technique to scan large networks and find which host is up and what services it is offering
- Advantages
    - It avoids the IDS and TCP three-way handshake. 
- Disadvantages 
    - It works on the UNIX platform only

### Ack flag probe
- Attackers send TCP probe packets with ACK flag set to a remote device and then analyzes the header information (TTL and WINDOW field) of received RST packets to find out if the port is open or closed
- ACK flag probe scanning can also be used to check the filtering system of target 
- Attackers send an ACK probe packet with a random sequence number, no response implies that the port is filtered (stateful firewall is present) and RST response means that the port is not filtered
    - no response: stateful firewall is present
    - no firewall: RST response
- types:
    - TTL-based ACK flag probe scanning
        -  port is less than the boundary value of 64, then that port is open
    - WINDOW based ACK flag probe scanning 
        - WINDOW value of RST packet on a particular port has a non-zero value, then that port is open

- Advantages:
    -This type of scan can evade IDS in most cases.
-  Disadvantages: 
    - This scan is very slow and can exploit only older operating systems with vulnerable BSD derived TCP/IP stacks.

### IDLE scan

### UDP Scanning
- cannot determine whether the host is alive, dead, or filtered. However, you can use one ICMP that checks for open or closed ports.
- UDP scan provides port information only
- if a UDP packet is sent to a port that is not open, the system will respond with an ICMP port unreachable message
## list scanning
- A list scan simply generates and prints a list of IPs/Names without actually pinging or scanning the hosts. 
- A reverse DNS resolution is carried out to identify the host names


### SSDP Scanning
- The attacker uses SSDP scanning to detect UPnP vulnerabilities that may allow him/her to launch buffer overflow or DoS attacks

## countermeasures

- Filter all ICMP messages (i.e. inbound ICMP message types and outbound ICMP type 3 unreachable messages) at the firewalls and routers
- Configure commercial firewalls to protect your network against fast port scans and SYN floods
-  Keep as few ports open as necessary and filter the rest, as the intruder will try to enter through any open port
- Block inbound ICMP message types and all outbound ICMP type-3 unreachable messages at border routers arranged in front of a company’s main firewall.
- Ensure that the mechanism used for routing and filtering at the routers and firewalls respectively cannot be bypassed using a particular source port or source-routing methods

# Scanning beyond IDS -- Firewall evasion techiques

### Packet Fragmentation 
- SYN/FIN Scanning Using IP Fragments:
    -  this method of processing involves greater CPU consumption as well as network resources, the configuration of most of the IDSs makes it skip fragmented packets during port scans
    - Since many IDSs use signature-based methods to indicate scanning attempts on IP and/or TCP headers, the use of fragmentation will often evade this type of packet filtering and detection, resulting in a high probability of causing problems on the target network. Attackers use SYN/FIN scanning method with IP fragmentation to evade this type of filtering and detection.
### Source routing
- refers to sending a packet to the intended destination with partially or completely specified route (without firewall-/IDS-configured routers) in order to evade IDS/firewall
### IP address DECOY
- IP address decoy technique refers to generating or manually specifying IP addresses of the decoys in order to evade IDS/firewall
- It appears to the target that the decoys as well as the host(s) are scanning the network
- This technique makes it difficult for the IDS/firewall to determine which IP address was actually scanning the network and which IP addresses were decoys 
- nMap:
    - nmap -D RND:10 [target] 
    - nmap -D decoy1,decoy2,decoy3,.. etc.
- IP address decoy is a useful technique for hiding your IP address. However, this cannot be successful if the target employs any of the active mechanisms like router path tracing, response-dropping, etc. Also, using many decoys can slow down the scanning process and affect the accuracy of scan performance

### IP address spoofing
- IP spoofing refers to changing the source IP addresses so that the attack appears to be coming from someone else 
- Attackers mostly use IP address spoofing to perform DoS attacks.
-  When the attacker sends a connection request to the target host, the target host replies and sends it to the spoofed IP address. When spoofing a nonexistent address, the target replies to a nonexistent system, and then hangs until the session times out, thus consuming the target’s resources
- using hping:
    - Hping3 www.certifiedhacker.com -a 7.7.7.7 
- IP Spoofing Detection Techniques
    - Direct TTL Probes :
        - Send packet to host of suspect spoofed packet that triggers reply and compare TTL with suspect packet; if the TTL in the reply is not as the same as the packet being checked, it implies that it is a spoofed packet
        - This technique is successful when the attacker is in a different subnet from that of the victim
    - IP identification number
        - Send probe to host of suspect spoofed traffic that triggers reply and compare the IP ID with suspect traffic
        - If IP IDs are not close in value to the packet being checked, suspect traffic is spoofed 
        - This technique is deemed successful even if the attacker is in the same subnet
    - TCP Flow Control Method:
        - Attackers sending spoofed TCP packets, will not receive the target's SYN-ACK packets 
        - Attackers cannot therefore be responsive to change in the congestion window size 
        - When received traffic continues after a window size is exhausted, most probably the packets are spoofed
- IP spoofing countermeasures
    - Avoid trust relationships => Do not rely on IP-based authentication.
    -  Use firewalls and filtering mechanisms
    - Use random initial sequence numbers 
    - Ingress filtering: prohibits spoofed traffic from entering the Internet.
    - Egress filtering refers to a practice that aims at IP spoofing prevention by blocking the outgoing packets with a source address that is not inside
    - SYN flooding countermeasures
    - enryption

### Proxy servers

-  proxy server is an application that can serve as an intermediary for connecting with other computers
- Attackers use proxy servers
    -  To hide the actual source of a scan and evade certain IDS/firewall restrictions. 
- proxy chaining:
    - tools:
        -  Proxy Switcher
        - Proxy Workbench
        - CyberGhost VPN
        - burp suite
    - tools for mobile:
        - shadowSocks
        - proxyDroid

### Anonnymizers

- An anonymizer is an intermediate server placed between you as the end user and the website to accesses the website on your behalf and make your web surfing untraceable. Anonymizers allow you to bypass Internet censors. An anonymizer eliminates all the identifying information (IP address) from your system while you are surfing the Internet, thereby ensuring privacy.

- types of anonimizers:
    - networked anonimyzers
    - single point anonymizers

# Banner grabbing

- An attacker uses banner grabbing techniques to identify network hosts running versions of applications and OSs with known exploits
- two types:
    - active:
        - Specially crafted packets are sent to remote OS and the responses are noted
        - The responses are then compared with a database to determine the OS
        - responses from different OSes varies due to differences in the TCP/IP stack implementation
    - passive:
        - Banner grabbing from error messages
        -  Error messages provide information such as the type of server, type of OS, and SSL tool used by the target remote system. 
        - Sniffing the network traffic: Capturing and analyzing packets from the target enables an attacker to determine the OS used by the remote system.
        -  Banner grabbing from page extensions 
- Given below are the four areas that typically determine the operating system: 
    - TTL (time to live) of the packets: What does the operating system sets as the Time To Live on the outbound packet?
    - Window Size: What is the Window size set by the operating system? - Whether the DF (Don’t Fragment) bit is set: Does the operating system set the Don’t Fragment bit?
    - TOS (Type of Service): Does the operating system set the Type of Service, and if so, what setting is it
- banner grabbing countermeasures:
    - Disabling or Changing Banner :
        - Apache 2.x with mod_headersmodule - use a directive in httpd.conf file to change banner information Header set Server “New Server Name”
        - Alternatively, change the ServerSignature line to ServerSignature Off in httpd.conf file
    -  Hiding File Extensions from Web Pages
        - File extensions reveal information about the underlying server technology

# Scanning pen testing

- the network scanning penetration test helps to determine the network's security posture by identifying live systems, discovering open ports, associating services, and grabbing system banners from a remote location to simulate a network hacking attempt

- Here is how you can conduct a pen-test of a target network:
    - Step 1: Perform host discovery
    - Step 2: Perform port scanning
    - Step 3: Scan beyond IDS and firewall
    - Step 4: Perform banner grabbing or OS fingerprinting 
    - Step 5: Draw network diagrams
    - Step 6: Document all the findings
    
    # notes
    
 ### protocols
 IRDP
The ICMP Router Discovery Protocol (IRDP) is a routing protocol that allows a host to discover the IP addresses of active routers on its subnet by listening to router advertisement and solicitation messages on its network. The attacker can add default route entries on a system remotely by spoofing router advertisement messages. Since IRDP does not require any authentication, the target host will prefer the default route defined by the attacker to the default route provided by the DHCP server. The attacker accomplishes this by setting the preference level and the lifetime of the route at high values to ensure that the target hosts will choose it as the preferred route.
ARP
Address Resolution Protocol (ARP) is a stateless TCP/IP protocol that maps IP network addresses to the addresses (hardware addresses) used by a data link protocol. Using this protocol, a user can easily obtain the MAC address of any device on a network.
DHCP
Dynamic Host Configuration Protocol (DHCP) is a client/server protocol that provides an IP address to an IP host. In addition to the IP address, the DHCP server also provides configuration related information such as the default gateway and subnet mask. When a DHCP client device boots up, it participates in traffic broadcasting.
DNS
DNS is the protocol that translates a domain name (e.g., www.eccouncil.org) into an IP address (e.g., 208.66.172.56). The protocol uses DNS tables that contain the domain name and its equivalent IP address stored in a distributed large database.

### ICMP 3/3

UDP port scanners use the UDP protocol instead of the TCP. There is no three-way handshake for UDP scan. The UDP protocol can be more challenging to use than the TCP scanning because you can send a packet, but you cannot determine whether the host is alive, dead, or filtered. However, you can use one ICMP that checks for open or closed ports. 

When a user sends a UDP packet to the target, either of the following can occur:

If the UDP port is open, the target accepts the packet and does not send any response.
If the UDP port is closed, the ICMP packet is sent in response.
The user will receive an ICMP Type 3 Code 3 response if the port is closed, and no response if the port is either open | filtered.

### nmap scripting engine

Nmap scripting engine (NSE) provides scripts that reveal all sorts of useful information from the target web server.

NSE is used in the following tasks:

Network discovery
More sophisticated version detection
Vulnerability detection
Backdoor detection
Vulnerability exploitation

### MBSA
Microsoft baseline security analyzer (MBSA) allows administrators to scan local and remote systems for missing security updates as well as common security misconfigurations in Microsoft Windows products.

### Tunelling scan over SSH
SSH protocol tunneling involves sending unencrypted network traffic through an SSH tunnel. For example, suppose you want to transfer files on an unencrypted FTP protocol, but the FTP protocol is blocked on the target firewall. The unencrypted data can be sent over encrypted SSH protocol using SSH tunneling. Pen tester makes use of this technique to bypass border sensors (e.g., firewall, IDS). 

### nmap timing options

Some of the timing options are as follows:

?        --delay <time> (Delay between probes)

?        --rate <rate> (Send probes at a given rate)

?        -d <time>, --delay <time> (Specify line delay)

?        -i <time>, --idle-timeout <time> (Specify idle timeout)

?        -w <time>, --wait <time> (Specify connect timeout)
    
    ### nmap
    
    -Pn (also known as No ping) Assume the host is up, thus skipping the host discovery phase, whereas P0 (IP Protocol Ping) sends IP packets with the specified protocol number set in their IP header.
-A This options makes Nmap make an effort in identifying the target OS, services, and the versions. It also does traceroute and applies NSE scripts to detect additional information.
The -O option turns on Nmap’s OS fingerprinting system. Used alongside the -v verbosity options, you can gain information about the remote operating system and about its TCP sequence number generation (useful for planning idle scans).
-sS Perform a TCP SYN connect scan. This just means that Nmap will send a TCP SYN packet just like
any normal application would do. If the port is open, the application must reply with SYN/ACK; however, to prevent half-open connections Nmap will send an RST to tear down the connection again.
-sT is an Nmap TCP connect scan and it is the default TCP scan type when SYN scan is not an option.
Since, Class C network starts its IP address from 192.0.0.0.











