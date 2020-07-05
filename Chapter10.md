#  DoS/DDoS Concepts

- Denial-of-Service (DoS) is an attack on a computer or network that reduces, restricts, or prevents accessibility of system resources to its legitimate users
- In a DoS attack, attackers flood the victim system with non-legitimate service requests or traffic to overload its resources
- In general, DoS attacks target network bandwidth or connectivity
- DoS attacks are a kind of security break that does not generally result in the theft of information.
- Distributed denial-of-service (DDoS) 
  - a coordinated attack which involves a multitude of compromised systems (Botnet) attacking a single target; thereby causing denial of service for users of the targeted system
  - The services under attack are those of the “primary victim,” whereas the compromised systems used to launch the attack are the “secondary victims.
  
# DoS/DDoS Attack Techniques

### Volumetric Attacks
- flood attack 
-  amplification attack 
  - engages the attacker or zombies to transfer messages to a broadcast IP address. This method amplifies malicious traffic that consumes victim systems’ bandwidth.

- The magnitude of attack is measured in bits-per-second (bps) 
- techniques
  - UDP flood attack 
    - An attacker sends spoofed UDP packets at a very high packet rate to a remote host on random ports of a target server using a large source IP range
    - Flooding of UDP packets causes server to repeatedly check for non-existent applications at the ports
    - Legitimate applications are inaccessible by the system and gives a error reply with an ICMP ‘Destination Unreachable’ packet
    - This attack consumes network resources and available bandwidth, exhausting the network until it goes offline
  - ICMP flood attack
    - CMP flood attack is a type of attack in which attackers send large volumes of ICMP echo request packets to a victim system directly or through reflection networks
    - To protect against ICMP flood attack, set a threshold limit, which when exceeded invokes the ICMP flood attack protection feature
  - Ping of Death attack
    - In Ping of Death (PoD) attack, an attacker tries to crash, destabilize, or freeze the targeted system or service by sending malformed or oversized packets using a simple ping command
  - Smurf attack
    - In Smurf attack, the attacker spoofs the source IP address with the victim’s IP address and sends large number of ICMP ECHO request packets to an IP broadcast network 

### Protocol attacks

- Consumes other types of resources like connection state tables present in the network infrastructure components such as load-balancers, firewalls, and application servers 
- The magnitude of attack is measured in packets-per-second (pps)
- techniques
  - SYN flood attack 
    - The attacker sends a large number of SYN request to target server (victim) with fake source IP addresses 
    - The target machine sends back a SYN ACK in response to the request and waits for the ACK to complete the session setup
    - no response
    - holding up each incomplete connection for 75 seconds can be cumulatively used as a Denial-of-Service attack
    - Countermeasures
      - Proper packet filtering
  - Fragmentation attack
    - These attacks destroy a victim’s ability to re-assemble the fragmented packets by flooding it with TCP or UDP fragments, resulting in reduced performance. 
    - Attacker sends large number of fragmented (1500+ byte) packets to a target web server with relatively small packet rate
  - ACK flood attack 
  - TCP state exhaustion attack

### Application layer atacks
- Consumes the application resources 
- techniques
  - HTTP GET/POST attack
    - In HTTP GET attack, the attackers use time delayed HTTP header to hold on to HTTP connections and exhaust web server resources
    - in HTTP POST attack, the attacker sends the HTTP requests with complete headers but incomplete message body to the target web server or application making the server wait for the rest of the message body
  - Slowloris attack
    - the attacker sends partial HTTP requests to the target web server or application 
    - Upon receiving the partial HTTP requests, the target server opens multiple open connections and keeps waiting for the requests to complete 
    - These requests will not be complete and as a result, the target server’s maximum concurrent connection pool will be filled up and additional connection attempts will be denied

###  multi-vector DDoS attacks
- the attackers use combinations of volumetric, protocol, and application-layer attacks to take down the target system or service
- These attacks are either launched one vector at a time or in parallel, in order to confuse a company’s IT department 

### peer to peer attack
- attackers instruct clients of peer-to-peer file sharing hubs to disconnect from their peer-to-peer network and to connect to the victim's fake website
- Attackers exploit flaws found in the network using DC++ (Direct Connect) protocol that is used for sharing all types of files between instant messaging clients
- Using this method, attackers launch massive denial-of-service attacks and compromise websites 

### Permanent Denial-of-Service Attack
- also known as phlashing, refers to attacks that cause irreversible damage to system hardware
- Unlike other DoS attacks, it sabotages the system hardware, requiring the victim to replace or reinstall the hardware
- This attack is carried out using a method known as “bricking a system” 
- Using this method, attackers send fraudulent hardware updates to the victims

### distributed reflection denial of service attack
- A distributed reflected denial of service attack (DRDoS), also known as spoofed attack, involves the use of multiple intermediary and secondary machines that contribute to the actual DDoS attack against the target machine or application 
- Attacker launches this attack by sending requests to the intermediary hosts; these requests are then redirected to the secondary machines which in turn reflects the attack traffic to the target 
- Advantage: 
  - The primary target seems to be directly attacked by the secondary victim, not the actual attacker 
  - Multiple intermediary victim servers are used, which results in increase in attack bandwidth
- countermeasure
    - Countermeasures
      -  Turn off the Character Generator Protocol (CHARGEN) service to stop this attack method

# botnets
- Bots are software applications that run automated tasks over the Internet and perform simple repetitive tasks, such as web spidering and search engine indexing 
- A botnet is a huge network of compromised systems and can be used by an attacker to launch denial-of-service attacks
- How Malicious Code Propagates?
  - Central Source Propagation
  - Back-Chaining Propagation
  - Autonomous Propagation
- Dyn dos attack
  - The Dyn attack, which took place on 21st October, 2016, is one of the largest data breaches in history which overturned a large portion of the internet in the United States and Europe and affected plenty of services 
  - The source of the attack was the Mirai botnets and it was launched by exploiting vulnerabilities in insecure Internet-of-Things devices such as internet protocol (IP) cameras, printers, and digital video recorders 
  - This abrupt large volume of data originated from various source IP addresses and were destined for destination port 53, where the data packets were composed of TCP and UDP packets

# Countermeasures

### detection techniques

- Activity Profiling
  - Activity profiling is done based on the average packet rate for a network flow, which consists of consecutive packets with similar packet fields
  - Activity profile is obtained by monitoring the network packet’s header information
  - An attack is indicated by:
  - An increase in activity levels among the network flow clusters
  - An increase in the overall number of distinct clusters (DDoS attack)


- Sequential Change-point Detection
  - Change-point detection algorithms isolate changes in network traffic statistics and in traffic flow rate caused by attacks 
  - The algorithms filter the target traffic data by address, port, or protocol and store the resultant flow as a time series
  - Sequential change-point detection technique uses Cusum algorithm to identify and locate the DoS attacks 
  - This technique can also be used to identify the typical scanning activities of the network worms

- Wavelet-based Signal Analysis

  - Wavelet analysis describes an input signal in terms of spectral components
  - Analyzing each spectral window’s energy determines the presence of anomalies
  - Wavelet-based signal analysis filters out the anomalous traffic flow input signals from background noise

### countermeasure strategies
- Absorbing the Attack
- Degrading Services
- Shutting Down the Services

### DDoS attack countermeasures
- Protect Secondary Victims 
- Neutralize Handlers 
  - There are usually few DDoS handlers deployed as compared to the number of agents. Neutralizing a few handlers can possibly render multiple agents useless, thus thwarting DDoS attacks
- Prevent Potential Attacks
- Deflect Attacks 
  -  use honeypots
- Mitigate Attacks 
  - Load Balancing
  - Throttling
    - Set routers to access a server with a logic to throttle incoming traffic levels that are safe for the server
    - This method helps routers manage heavy incoming traffic, so that the server can handle it
    - It filters legitimate user traffic from fake DDoS attack traffic
  - Drop Requests
    - In this technique, servers and routers drop packets when load increases
- Post-attack Forensics
  - Traffic Pattern Analysis
  - Packet Traceback
    - like reverse engineering
    - It helps in identifying the true source of attack and taking necessary steps to block further attacks
  - Event Log
    - Event log analysis helps in identifying the source of the DoS traffic Analysis

### Prevent Potential Attack
- Egress filtering 
  - scans the headers of IP packets leaving a network. If the packets pass the specifications, they can route out of the sub-network from which they originated. The packets will not reach the targeted address if they do not meet the necessary specifications. Egress filtering ensures that unauthorized or malicious traffic never leaves the internal network. 
- Ingress filtering 
  - prevents source address spoofing of Internet traffic
- TCP intercept 
  - is a traffic-filtering feature in routers to protect TCP servers from a TCP SYN-flooding attack, a kind of DoS attack
- Rate limiting 
  -  a technique used to control the rate of outbound or inbound traffic of a network interface controller.

### Techniques to Defend against Botnets
- RFC 3704  filtering
  - is a basic ACL filter, which limits the impact of DDoS attacks, by denying traffic with spoofed addresses.
  -  This filter requires packets sourced from valid, allocated address space, consistent with the topology and space allocation. 
  -  A “bogon list” consists of all unused or reserved IP addresses that should not come in from the Internet
- Cisco IPS Source IP Reputation Filtering
- Black-Hole Filtering 
  - Black-hole filtering is a common technique to defend against botnets and thus to prevent DoS attacks. Black hole refers to network nodes where incoming traffic is discarded or dropped without informing the source that the data did not reach the intended recipient.
- DDoS Prevention Offerings from ISP or DDoS Service 

### DoS/DDoS Protection at ISP Level
- One of the best ways to defend against DoS attacks is to block them at the gateway. This
happens by the contracted ISP. ISPs offer “clean pipes” service-level agreement that promises to an assured bandwidth of genuine traffic rather than just total bandwidth of all traffic. Most ISPs simply block all requests during a DDoS attack, denying even legitimate traffic from accessing the service.

### Enabling TCP Intercept on Cisco IOS Software
- PAGE 1093

# Notes

### peer to peer attack

- uses DC++
- Peer-to-peer attack is a form of DDoS attack. In this kind of attack, the attacker exploits a number of bugs in peer-to-peer servers to initiate a DDoS attack. Unlike a botnet-based attack, a peer-to-peer attack eliminates the need for attackers to communicate with the clients it subverts. Here, the attacker instructs clients of large peer-to peer file-sharing hubs to disconnect from their peer-to-peer network and instead, to connect to the victim’s website. With this, several thousand computers may aggressively try to connect to a target website, which decreases the performance of the target website.


### countermeasures

- Ingress filtering
  -  protects against flooding attacks that originate from valid prefixes (IP addresses). 
- Egress filtering
  -  scans the headers of IP packets going out of the network.

- TCP intercept mode
   - the router intercepts the SYN packets sent by the clients to the server and matches with an extended access list. If there is a match, then on behalf of the destination server, the intercept software establishes a connection with the client. Similarly, the intercept software also establishes a connection with the destination server on behalf of the client. Once the two half connections are established, the intercept software combines them transparently.
   - Thus, the TCP intercept software prevents the attempts of fake connection from reaching the server. It acts as a mediator between the server and the client throughout the connection.

- MAC address filtering 
  - allows you to define a list of devices and only allows those devices on your network.

### random stuff

- Smurf attack
  -  the attacker spoofs the source IP address with the victim’s IP address and sends large number of ICMP ECHO request packets to an IP broadcast network. This causes all the hosts on the broadcast network to respond to the received ICMP ECHO requests. These responses will be sent to the victim’s machine since the IP address is spoofed by the attacker. This causes significant traffic to the actual victim’s machine, ultimately leading the machine to crash.
- Change-point detection technique 
  - filters network traffic by IP addresses, targeted port numbers, and communication protocols used, and stores the traffic flow data in a graph that shows the traffic flow rate versus time.
  






