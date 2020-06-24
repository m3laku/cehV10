# IDS concepts

###  intrusion detection system (IDS) 
-  a security software or hardware device which inspects all inbound and outbound network traffic for suspicious patterns that may indicate a network or system security breach 
-  The IDS checks traffic for signatures that match known intrusion patterns, and signals an alarm when a match is found
-  Depending on the traffic to be monitored, the IDS is placed outside/inside the firewall to monitor suspicious traffic originating from outside/inside the network
-  Placed inside, the IDS will be ideal if it is near a DMZ; however, the best practice is to use a layered defense by deploying one IDS in front of the firewall and another one behind the firewall in the network.
-  The primary purpose of the IDS is to recognize and provide real-time monitoring of intrusions. 

### How IDS Detects an Intrusion

- Signature recognition
  - also known as misuse detection, tries to identify events that indicate an abuse of a system or network resource
- Anomaly Detection
  - It detects the intrusion based on the fixed behavioral characteristics of the users and components in a computer system
- Protocol Anomaly Detection
  - in this type of detection, models are built to explore anomalies in the way vendors deploy the TCP/IP specification

### Types of Intrusion Detection Systems
- Network-Based Intrusion Detection Systems
  - check every packet entering the network for the presence of anomalies and incorrect data
- Host-Based Intrusion Detection Systems
  -  analyze each system’s behavior. Install Host-Based Intrusion Detection Systems (HIDSs) on any system ranging from a desktop PC to a server. The HIDS is more versatile than the NIDS. In addition to detecting unauthorized insider activity, host-based systems are also effective at detecting unauthorized file modification. HIDSs focuses on the changing aspects of local systems
-  Log File Monitoring
   -  searches through the logs and identifies malicious events. In a similar manner to NIDS, these systems look for patterns in the log files that suggest an intrusion
- File Integrity Checking
  -  These mechanisms check for Trojan horses, or modified files, indicating the presence of an intruder. Tripwire is an example of a file integrity checking tool.

# firewall concepts

- Firewalls are hardware and/or software designed to prevent unauthorized access to or from a private network 
- They are placed at the junction or gateway between the two networks, which is usually a private network and a public network such as the Internet
- Firewalls examine all messages entering or leaving the Intranet and block those that do not meet the specified security criteria


- types of firewalls
  -  hardware firewall 
     -   either a dedicated stand-alone hardware device or it comes as part of a router 
     -   The network traffic is filtered using the packet filtering technique
     -   it is used to filter out the network traffic for large business networks
   - software firewall
     -  is a software program installed on a computer, just like normal software It is generally used to filter traffic for individual home users It only filters traffic for the computer on which it is installed, not for the network
-  firewall technologies:   PAGE 1198
   - Packet Filtering 
     - Packet filtering firewalls work at the network layer of the OSI model (or the IP layer of TCP/IP). 
     - They are usually a part of a router
     - In a packet filtering firewall, each packet is compared to a set of criteria before it is forwarded 
     - Depending on the packet and the criteria, the firewall can drop the packet or forward it, or send a message to the originator 
     - Rules can include the source and the destination IP address, the source and the destination port number, and the protocol used

   - Circuit Level Gateways 
     - Circuit-level gateways work at the session layer of the OSI model (or the TCP layer of TCP/IP) 
     - Information passed to a remote computer through a circuit-level gateway appears to have originated from the gateway 
     - They monitor requests to create sessions, and determine if those sessions will be allowed
     - Circuit proxy firewalls allow or prevent data streams; they do not filter individual packets
   - Application Level Firewall 
     - Application-level gateways examine traffic and filter on application-specific commands such as http:post and get
     - Being proxy-based, they can permit or deny traffic according to the authenticity of the user or process involved.
     - Incoming and outgoing traffic is restricted to services supported by proxy; all other service requests are denied
     - Active vs Passive application level firewalls

   - Stateful Multilayer Inspection 
     - Stateful multilayer inspection firewalls combine the aspects of the other three types of firewalls (Packet Filtering, Circuit Level Gateways, and Application Level Firewall) 
     - They filter packets at the network layer of the OSI model (or the IP layer of TCP/IP), to determine whether session packets are legitimate, and they evaluate the contents of packets at the application layer
   - Application Proxies 
     - An application-level proxy works as a proxy server and filters connections for specific services
     - It filters connections based on the services and protocols, when acting as proxies
   - Virtual Private Network 
     - A VPN is a private network constructed using public networks, such as the Internet
     - It is used for the secure transmission of sensitive information over an untrusted network, using encapsulation and encryption
     - It establishes a virtual point-to-point connection through the use of dedicated connections
     - Only the computing device running the VPN software can access the VPN 
   - Network Address Translation
- Limitations
  - A firewall does not prevent the network from new viruses, backdoor and insider attacks 
  - A firewall cannot do anything if the network design and configuration is faulty A firewall is not an alternative to antivirus or antimalware
  -  A firewall cannot prevent social engineering threats 
  -  A firewall does not prevent passwords misuse
  -   A firewall does not block attacks from a higher level of the protocol stack 
  -   A firewall does not protect against attacks from dial-in connections and attacks originating from common ports and applications 
  -   A firewall is unable to understand tunneled traffic

# Honeypot Concepts
- A honeypot is an information system resource that is expressly set up to attract and trap people who attempt to penetrate an organization’s network
- It has no authorized activity, does not have any production value, and any traffic to it is likely a probe, attack, or compromise
- A honeypot can log port access attempts, or monitor an attacker's keystrokes.
-  These could be early warnings of a more concerted attack
-  types
   -  low interaction Honeypot
      -  These honeypots simulate only a limited number of services and applications of a target system or network 
      -  Generally, set to collect higher level information about attack vectors such as network probes and worm activities
   - high interaction Honeypot
     - These honeypots simulates all services and applications 
     - Capture complete information about an attack vector such as attack techniques, tools and intent of the attack
   - production Honeypot
     - These honeypots emulate real production network of an organization
     - generally, set to collect internal flaws and attackers within an organization
   - research Honeypot
     - These are high interaction honeypots primarily deployed in research institutes, government or military organizations 
     - Capture in-depth information about the way an attack is performed, vulnerabilities exploited and the attack techniques used by the attackers
# IDS, firewall and honeypot solutions

### Snort

- Snort is an open source network intrusion detection system, capable of performing real-time traffic analysis and packet logging on IP networks
- It can perform protocol analysis and content searching/matching, and is used to detect a variety of attacks and probes, such as buffer overflows, stealth port scans, OS fingerprinting attempts, etc
- Uses of Snort: 
  - packet sniffer 
  -  Packet logger 
  -  network intrusion prevention system
-  two logical parts: 
   -  Rule header: Identifies rule’s actions such as alerts, log, pass, activate, dynamic, etc.
   -   Rule options: Identifies rule’s alert messages
- the rules should be
  - robust
  - flexible
- Three available actions in Snort:
  -  Alert 
     -  Generate an alert using the selected alert method, and then log the packet Log - 
  - Log 
  - Pass 
    -  Drop (ignore) the packet
- protocols snort supports
  - udp
  - tcp
  - icmp

# Evading IDS

### techniques

- Insertion Attack 
  -  Insertion is the process in which the attacker confuses the IDS by forcing it to read invalid packets
  -  An IDS blindly believes and accepts a packet that an end system rejects and an attacker exploits this condition and inserts data into the IDS
  -  This attack occurs when NIDS is less strict in processing packets than the internal network 
  -  The attacker obscures extra traffic and IDS concludes the traffic is harmless. Hence, the IDS gets more packets than the destination
- Evasion 
  - In this evasion technique, an end system accepts a packet that an IDS rejects 
  - Using this technique, an attacker exploits the host computer without the IDS ever realizing it
  - The attacker sends portions of the request in packets that the IDS mistakenly rejects, allowing the removal of parts of the stream from the IDS
- Denial-of-Service Attack
  - Many IDSs use a centralized server for logging alerts
  - If attackers know the IP address of the centralized server they can perform DoS or other hacks to slow down or crash the server 
  - As a result, attackers intrusion attempts will not be logged

- Obfuscating
  - Obfuscating is an IDS evasion technique used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS
  - Attackers can encode attack patterns in unicode to bypass IDS filters, but be understood by an IIS web server
- False Positive Generation 
- Session Splicing
  - A technique used to bypass IDS where an attacker splits the attack traffic in to many packets such that no single packet triggers the IDS
  - It is effective against IDSs that do not reconstruct packets before checking them against intrusion signatures
  - If attackers are aware of delay in packet reassembly at the IDS, they can add delays between packet transmissions to bypass the reassembly
  - IDS will stop working if the target host keeps session active for a time longer than the IDS reassembly time 
  - Many IDSs stops reassembly if they do not receive packets within a certain time
  - Any attack attempt after a successful splicing attack will not be logged by the IDS 
- Unicode Evasion 
  - some IDS systems handle Unicode improperly as Unicode allows multiple interpretations of the same characters
  - Taking this as an advantage, attackers can convert attack strings to Unicode characters to avoid pattern and signature matching at the IDS

- fragmentation Attack 
  - Fragmentation can be used as an attack vector when fragmentation timeouts vary between IDS and host
  - If fragment reassembly timeout is 10 seconds at the IDS and 20 seconds at the target system, attackers will send the second fragment after 15 seconds of sending the first fragment
  - In this scenario, the IDS will drop the fragment as the second fragment is received after its reassembly time but the target system will reassemble the fragments
  - Attackers will keep sending the fragments with 15 second delays until all the attack payload is reassembled at the target system

- Overlapping Fragments
- Time-To-Live Attacks
  - These attacks require the attacker to have a prior knowledge of the topology of the victim's network
  - This information can be obtained using tools such as traceroute which gives information on the number of routers between the attacker and the victim
  - steps
    1. Attacker breaks malicious traffic into 3 fragments Attacker
    2. Attacker sends frag 1 with high TTL, false frag 2 with low TTL
    3. IDS receives both fragments, victim receives first fragment only
    4. Attacker sends frag 3 with high TTL
    5. IDS reassembles 3 fragments into meaningless packet and drops
    6. Victim receives real frag 2, and suffers attack, while no log entry created
- Invalid RST Packets
- Urgency Flag
  - Many IDSs do not consider the urgent pointer and process all the packets in the traffic whereas the target system process only the urgent data
  - This results in the IDS and the target systems having different sets of packets, which can be exploited by attackers to pass the attack traffic
- Polymorphic Shellcode 
  - Polymorphic shellcode attacks include multiple signatures making it difficult to detect the signature
  - Attackers encode the payload using some technique and then place a decoder before the payload 
  - As a result of this the shellcode is completely rewritten each time it is sent evading detection
  - This technique also evades the commonly used shellcode strings, thus making shellcode signatures unusable

- ASCII Shellcode 
  - Attackers can use ASCII shellcode to bypass the IDS signature as the pattern matching does not work effectively with the ASCII values
- Application-Layer Attacks
  - IDS cannot verify the signature of compressed file format 
  - This enables an attacker to exploit the vulnerabilities in compressed data
  - This makes the detection of attack traffic extremely difficult at the IDS
- Desynchronization 
  -  Pre-Connection SYN: 
     -  This attack is performed by sending an initial SYN before the real connection is established, but with an invalid TCP checksum. The IDS can ignore or accept subsequent SYNs in a connection. If a SYN packet is received after the TCP control block is opened, the IDS resets the appropriate sequence number to match the newly received SYN packet. Attackers send fake SYN packets with a completely invalid sequence number to desynchronize the IDS. This stops IDS from monitoring all, legitimate and attack, traffic. If IDS is smart, it does not check the TCP checksum. If the IDS checks the checksum, the attack is synchronized, and a bogus sequence number is sent to the IDS before the real connection occurs.
  -  Post-Connection SYN: 
     -  For this technique, attempt to desynchronize the IDS from the actual sequence numbers that the kernel is honoring. Send a post connection SYN packet in the data stream, which will have divergent sequence numbers, but otherwise meet all of the necessary criteria to be accepted by the target host. However, the target host will ignore this SYN packet, as it references an already established connection. This attack intends to get the IDS to resynchronize its notion of the sequence numbers to the new SYN packet. It will then ignore any data that is a legitimate part of the original stream because it will be awaiting a different sequence number. Once succeeded in resynchronizing the IDS with a SYN packet, send an RST packet with the new sequence number and close down its notion of the connection
- Encryption 
  - When the attacker has already established an encrypted session with the victim, it results in the most effective evasion attack
- Flooding
  - The attacker sends loads of unnecessary traffic to produce noise, and if IDS does not analyze the noise traffic well, then the true attack traffic may go undetected
# Evading firewalls

### techniques

- Port Scanning
  - Some firewalls will uniquely identify themselves in response to simple port scans
- Firewalking 
  - A technique that uses TTL values to determine gateway ACL filters and map networks by analyzing IP packet responses
  - Attackers send a TCP or UDP packet to the targeted firewall with a TTL set to one hop greater than that of the firewall
  - If the packet makes it through the gateway, it is forwarded to the next hop where the TTL equals one and elicits an ICMP "TTL exceeded in transit" to be returned, as the original packet is discarded
  - This method helps locate a firewall. Additional probing permits fingerprinting and identification of vulnerabilities
- Banner Grabbing
  - The three main services which send out banners are FTP, telnet, and web servers
  - An example of SMTP banner grabbing is: telnet mail. targetcompany.org 25

- IP Address Spoofing 
- Source Routing 
- Tiny Fragments 
  - The attack will succeed if the filtering router examines only the first fragment and allows all the other fragments to pass through 
  - This attack is used to avoid user defined filtering rules and works when the firewall checks only for the TCP header information
- Using IP Address in Place of URL 
- Using Anonymous Website Surfing Sites
  - These services hide the actual IP address of the surfer and enable bypassing the IP-based firewall filter rules
- Using Proxy Server
- ICMP Tunneling 
- ACK Tunneling 
  - Some firewalls do not check packets with ACK bit set because ACK bits are supposed to be used in response to legitimate traffic Tools such as AckCmd (http://ntsecurity.nu) can be used to implement ACK tunneling
- HTTP Tunneling
  - This method can be implemented if the target company has a public web server with port 80 used for HTTP traffic, that is unfiltered on its firewall
  - Encapsulates data inside HTTP traffic (port 80) 
- SSH Tunneling 
  -  Example: 
  -  ssh –f user@certifiedhacker.com –L 5000:certifiedhacker.com:25 –N 
     -  -f => background mode, 
     -  user@certifiedhacker.com => username and server you are logging into
     -  -L 5000:certifiedhacker.com:25 => local-port:host:remote-port, 
     -   -N => Do not execute the command on the remote system.

- Through External Systems 
- Through MITM Attack 
- Through Content 
  - In this method, the attacker sends the content containing malicious code to the user and tricks him/her to open it so that the malicious code can be executed
- Through XSS Attack

# Detecting Honeypots

- Ports that show a particular service running but deny a three-way handshake connection indicate the presence of a honeypot

### techniques
- Detecting presence of Layer 7/4/2 Tar Pits
- Detecting Honeypots running on VMware



