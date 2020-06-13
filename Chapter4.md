# Enumeration concepts
- In the enumeration phase, attacker creates active connections with system and performs directed queries to gain more information about the target
- Enumeration techniques work in an intranet environment
- techniques for enumeration:
  -  Extract user names using email IDs
  -  Extract information using default passwords
  -  Brute force Active Directory
  -  Extract information using DNS Zone Transfer
  -  Extract user groups from Window:
     -  to extract user groups from Windows, the attacker should have a registered ID as a user in the Active Directory. The attacker can then extract information from groups in which the user is a member by using the Windows interface or command line method
  -  Extract user names using SNMP
- services and ports to enumerate:
  - TCP/UDP 53: DNS Zone Transfer 
  - TCP/UDP 135: Microsoft RPC Endpoint Mapper 
    - RPC is a protocol used by a client system to request a service from the server
  - UDP137: NetBIOS 
    -  NetBIOS Name Servers maintain a database of the NetBIOS names for hosts and the corresponding IP address
 - UDP139: netbios:
   - This is perhaps the most well-known Windows port. It is used to transfer files over a network. Systems use this port for both NULL Session establishment and file and printer sharing. A system administrator considering restricting access to ports on a Windows system should make TCP 139 a top priority. An improperly configured TCP 139 port can allow an intruder to gain unauthorized access to critical system files or the complete file system, resulting in data theft or other malicious activities
 - TCP/UDP 445: SMB over TCP
   - PRINTER RELATED
 - UDP 161: Simple Network Management protocol (SNMP) 
 - TCP/UDP 162: SNMP Trap
 - TCP/UDP 389: Lightweight Directory Access Protocol (LDAP)
-  TCP/UDP 3268: Global Catalog Service
-  TCP 25: Simple Mail Transfer Protocol (SMTP)
-  UDP 500: ISAKMP/Internet Key Exchange (IKE)
-  TCP/UDP 5060, 5061: Session Initiation Protocol (SIP)
   -  for voice and video calls
  # NetBios Enumeration

- NetBIOS name is a unique 16 ASCII character string used to identify the network devices over TCP/IP, 15 characters are used for the device name and the 16th character is reserved for the service or name record type
- Windows uses NetBIOS for file and printer sharing.
- Microsoft does not support NetBIOS name resolution for Internet Protocol Version 6 (IPv6). 
- Attackers use the NetBIOS enumeration to obtain:
    - List of computers that belong to a domain
    - List of shares on the individual hosts in the network
    - Policies and passwords
- commands
  - nbtstat.exe –c
    - to get the contents of the NetBIOS name cache,
the table of NetBIOS names, and their resolved IP addresses
  - nbtstat.exe –a <IP address of the remote machine>
    - to get the NetBIOS name table of a remote compute
- nmtstat syntacs
  -   nbtstat [-a RemoteName] [-A IPAddress] [-c] [-n] [-r] [-R] [-RR] [-s] [-S] [Interval] 

### enunmerating user accounts
- Enumerating user accounts using PsTools suite helps to control and manage remote systems from the command line.
- PsTools commands:
  - PsExec - execute processes remotely 
  - PsFile - shows files opened remotely 
  - PsGetSid-display the SID of a computer or a user 
  - PsKill - kill processes by name or process ID 
  - PsInfo - list information about a system
  - PsList - list detailed information about processes
  - PsLoggedOn - see who's logged on locally and via resource sharing
  - PsLogList - dump event log records 
  - PsPasswd - changes account passwords
  - PsShutdown - shuts down and optionally reboots a computer

### Enumerating Shared Resources Using Net View 
-  Net View is a command line utility that displays a list of computer or network resources. It displays a list of computers in the specified workgroup or shared resources available on the specified computer
-   Usage:
    - net view \<computername> 
      - Where<computername> is the name of a specific computer, whose resources you want to view 
    - net view workgroup: workgroupname
      - where workgroupname is the name of the workgroup, whose shared resources you want to view

# SNMP enumeration

- SNMP enumeration is the process of creating a list of the user’s accounts and devices on a target computer using SNMP
- SNMP (Simple Network Management Protocol) is an application layer protocol that runs on UDP and maintains and manages routers, hubs, and switches on an IP network. SNMP agents run on Windows and UNIX networks on networking devices.

- SNMP consists of a manager and an agent; agents are embedded on every network device, and the manager is installed on a separate computer
- SNMP holds two passwords to access and configure the SNMP agent from the management station:
  - read community string
  - read/write community string
- Attackers enumerate SNMP to extract information about network resources such as hosts, routers, devices, shares, etc. and network information such as ARP tables, routing tables, traffic, etc.
- Management Information Base (MIB):
  - MIB is a virtual database containing formal description of all the network objects that can be managed using SNMP
  - The MIB database is hierarchical and each managed object in a MIB is addressed through Object Identifiers (OIDs)
  - 2 tyoes of managed objects exist:
    - scalar
    - tabular
  - A user can access the contents of the MIB using a web browser either by entering the IP address and Lseries.mib or by entering DNS library name and Lseries.mib.
  
# LDAP enumeration

- Lightweight Directory Access Protocol (LDAP) is an Internet protocol for accessing distributed directory services
- Directory services may provide any organized set of records, often in a hierarchical and logical structure, such as a corporate email directory
- A client starts a LDAP session by connecting to a Directory System Agent (DSA) on TCP port 389 and then sends an operation request to the DSA
- Information is transmitted between the client and the server using Basic Encoding Rules (BER)
- Attacker queries LDAP service to gather information such as valid user names, addresses, departmental details, etc. that can be further used to perform attacks

# NTP enumeration

- Attacker queries NTP server to gather valuable information such as: 
  - List of hosts connected to NTP server
  -  Clients IP addresses in a network, their system names and Oss
  -  Internal IPs can also be obtained if NTP server is in the demilitarized zone (DMZ)
  -  commands:
     -  ntpdate
        -   This command collects the number of time samples from a number of time sources.
       -  ntptrace 
          -  This command determines from where the NTP server gets time and follows the chain of NTP servers back to its prime time source
      - ntpdc
        - This command queries the ntpd daemon about its current state and requests changes in that state. 
      - ntpq 
        - This command monitors NTP daemon ntpd operations and determine performance.
  
  # SMTP enumeration

  
- SMTP provides 3 built-in-commands: 
  - VRFY - Validates users 
  - EXPN - Tells the actual delivery addresses of aliases and mailing lists 
  - RCPT TO - Defines the recipients of the message
- SMTP servers respond differently to VRFY, EXPN, and RCPT TO commands for valid and invalid users from which we can determine valid users on SMTP server
- Attackers can directly interact with SMTP via the telnet prompt and collect list of valid users on the SMTP server 
  # DNS Enumeration using zone transfer
  - It is a process for locating the DNS server and the records of a target network 
  - An attacker can gather valuable network information such as DNS server names, host names, machine names, user names, IP addresses, etc. of the potential targets 
  - In DNS zone transfer enumeration, an attacker tries to retrieve a copy of the entire zone file for a domain from the DNS server
  - To perform a DNS zone transfer, the attacker sends a zone transfer request to the DNS server pretending to be a client; the DNS server then sends a portion of its database as a zone to you. This zone may contain a lot of information about the DNS zone network

# IPSec Enumeration
- IPsec uses ESP (Encapsulation Security Payload), 
 AH (Authentication Header) and IKE (Internet Key Exchange) to secure communication between virtual private network (VPN) end points
- Most IPsec based VPNs use Internet Security Association and Key Management Protocol (ISAKMP), a part of IKE, to establish, negotiate, modify, and delete Security Associations (SA) and cryptographic keys in a VPN environment
- A simple scanning for ISAKMP at UDP port 500 can indicate the presence of a VPN gateway
- Attackers can probe further using a tool such as ike-scan to enumerate the sensitive information including encryption and hashing algorithm, authentication type, key distribution algorithm, SA LifeDuration, etc
- You can enter the following command to perform Nmap scan for checking the status of isakmp over port 500:
  -   nmap –sU –p 500 <target IP address>
 - ike-scan:
   -  enumerate the sensitive information including encryption and hashing algorithm, authentication type, key distribution algorithm, SA LifeDuration, etc. In this type of scan, specially crafted IKE packets with ISAKMP header are sent to the target gateway and the responses are recorded
   -  discovers IKE hosts and can also fingerprint them using the retransmission backoff pattern.

# VoIP enumeration

- VoIP uses SIP (Session Initiation Protocol) protocol to enable voice and video calls over an IP network
- SIP service generally uses UDP/TCP ports 2000, 2001, 5050, 5061
- VoIP enumeration provide sensitive information such as VoIP gateway/servers, IP-PBX systems, client software (softphones) /VoIP phones User-agent IP addresses and user extensions
- This information can be used to launch various VoIP attacks such as Denial-of-Service (DoS), Session Hijacking, Caller ID spoofing, Eavesdropping, Spamming over Internet Telephony (SPIT), VoIP phishing (Vishing), etc.

# RPC enumeration

- Remote Procedure Call (RPC) allows client and server to communicate in distributed client/server programs
- Enumerating RPC endpoints enable attackers to identify any vulnerable services on these service ports
- nmap commands:
  -  nmap -sR <target IP/network> 
  -  nmap -T4 –A <target IP/network>

# Unix/Linux User Enumeration 
- commands
  - rusers
    -  displays a list of users who are logged on to remote machines or machines on local network.
  -  rwho
     -   displays a list of users who are logged in to hosts on the local network.
  - finger
    -  displays information about system users such as user’s login name, real name, terminal name, idle time, login time, office location and office phone numbers

# enumeration countermeasures

- PAGE 426





  
   





