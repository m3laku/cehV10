
# Vulnerability assessment concepts
- In a network there are generally two main causes for systems being vulnerable, software or hardware misconfiguration and poor programming practices

- Vulnerability research:
  - Vulnerabilities are classified based on:
    -  severity level (low, medium, or high) 
    -  exploit range (local or remote)
- vulnerabilty classificagtion
  - Misconfiguration
  - default installation
  - Buffer Overflows
  - design flaws:
    - Design vulnerabilities such as incorrect encryption or poor validation of data, refer to logical flaws in the functionality of the system that is exploited by the attackers
  - operationg system flaws
  - application flaws
  - open services
  - default passwords
- what is vulnerability assessment
  - an examination of the ability of a system or application, including current security procedures and controls, to withstand assault
  - There are two approaches to network vulnerability scanning: 
    -  Active Scanning: 
       -  The attacker interacts directly with the target network to find vulnerabilities. Example: An attacker sends probes and specially crafted requests to the target host in the network in order to identify vulnerabilities.
    - Passive Scanning: 
      - The attacker tries to find vulnerabilities without directly interacting with the target network. The attacker identifies vulnerabilities via information exposed by systems in their normal communications.
- types of vulnerability assessmnets:
  - Active Assessment
    - Uses a network scanner to find hosts, services, and vulnerabilities
  - Passive Assessment
  - External Assessment
  - Internal Assessment
  - Host-based Assessment :
    -  a type of security check that involves carrying out a
configuration-level check through the command line
  - network assessment
  - Application Assessments
    - An application assessment focuses on transactional Web applications, traditional client-server applications, and hybrid systems
  - Wireless Network Assessments
- vulnerability management life cycle
  - Creating Baseline
    -  In this phase, critical assets are identified and prioritized to create a good baseline for the vulnerability management. 
   - Vulnerability Assessment
   - Risk Assessment:
      -   In this phase, all the serious uncertainties that are associated with the system are assessed, fixed, and permanently eliminated for ensuring a flaw free system. Risk assessment summarizes the vulnerability and risk level identified for each of the selected asset. It determines the risk level for a particular asset, whether it is high, moderate or low.
  - Remediation
    -   Remediation is the process of reducing the severity of vulnerabilities.
  - Verification
  - Monitor
- vulnerability management phases
  - pre assessment phase: 
    - creating baseline
    - Pre-assessment phase refers to the preparatory phase, which includes defining policies and standards, defining the scope of assessment, designing appropriate information protection procedure, and identifying and prioritizing the critical assets to create a good baseline for the vulnerability management.
  - vulnerability assessment phase
  -  Post Assessment Phase:
     -   Post assessment phase is also known as the recommendation phase, which is performed after the risk assessment. Post-assessment is based on the risk assessment.
     -   Post assessment includes:
         -    risk assessment, 
         -    remediation, 
         -    verification,
         -    monitoring

# Vulnerability assessment solutions

- Vulnerability assessment solution is an important tool for information security management as it identifies all the security weaknesses before an attacker can exploit them

### product based solution VS Service based solution

- Product-based solutions are installed in the organization’s internal network
- Service-based solutions are offered by third parties, such as auditing or security consulting firms.

### tree based assessment vs interface based assessmneet

### types of vulnerability sassessment tools

- Host-Based Vulnerability Assessment Tools 
  - The host-based scanning tools are apt for servers that run various applications such as the web, critical files, databases, directories, and remote accesses.
- depth assessment tools
  - Depth assessment tools are used to find and identify previously unknown vulnerabilities in a system
- Application-Layer Vulnerability Assessment Tools
  - Application-layer vulnerability assessment tools are designed to serve the needs of all kinds of operating system types and applications
- Scope assessment tools
  -  provides assessment of the security by testing vulnerabilities in the applications and operating system
- Active/Passive assessment tools
  - Active scanners perform vulnerability checks on the network that consume resources on the network
  - Passive scanners are those that do not affect system resources considerably, as they only observe system data and perform data processing on a separate analysis machine.
- Location/Data Examined Tools

### criteria for choosing vulnerability assessment tools
- Types of vulnerabilities being assessed 
- Testing capability of scanning 
- Ability to provide accurate reports 
- Efficient and accurate scanning 
- Capability to perform a smart search 
- Functionality for writing own tests Test run scheduling

# Vulnerability scooring Systems
- Vulnerability scoring systems and vulnerability databases are used by security analysts to rank information system vulnerabilities, and to provide a composite score of the overall severity and risk associated with identified vulnerabilities. Vulnerability databases collect and maintain information about various vulnerabilities present in the information systems.

### Common Vulnerability Scoring System

- CVSS provides an open framework for communicating the characteristics and impacts of IT vulnerabilities
- Its quantitative model ensures repeatable accurate measurement while enabling users to see the underlying vulnerability characteristics that were used to generate the scores
- Two common uses of CVSS are 
  - prioritization of vulnerability remediation activities
  - calculating the severity of vulnerabilities discovered on one's systems
- The National Vulnerability Database (NVD) provides CVSS scores for almost all known vulnerabilities
- CVSS assessment consists of three metrics for measuring vulnerabilities:
  - Base Metrics: 
    - It represents the inherent qualities of a vulnerability
  - Temporal Metrics: 
    - It represents the features that keep on changing during the lifetime of a vulnerability.
  -  Environmental Metrics:
     -   It represents the vulnerabilities that are based on a particular environment or implementation.

### Common Vulnerabilities and Exposures (CVE)

-  A dictionary rather than a database
 - list or dictionary of standardized identifiers for common software vulnerabilities and exposures
 -  CVE IDs also provide a baseline for evaluating the coverage of tools and services so that users can determine which tools are most effective and appropriate for their organization’s needs. In short, products and services compatible with CVE provide better coverage, easier interoperability, and enhanced security.

### National Vulnerability Database (NVD)
- The NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP). This data enables automation of vulnerability management, security measurement, and compliance. The NVD includes databases of security checklist references, security related software flaws, misconfigurations, product names, and impact metrics


### Vulnerability Assessment Tools

- Qualys VM 
  -  a cloud-based service that gives you immediate global visibility into where your IT systems might be vulnerable to the latest Internet threats and how to protect them
  -  It helps you to continuously identify threats and monitor unexpected changes in your network before they turn into breaches
  -   Features: 
      -  Agent-based detection
      -  Constant monitoring and alerts
      -   Comprehensive coverage and visibility
      -   VM for the perimeter-less world
- Nessus 
  - the vulnerability scanning platform for auditors and security analysts. Users can schedule scans across multiple scanners, use wizards to easily and quickly create policies, schedule scans and send results via email
- GFI LanGuard 
  - scans, detects, assesses and rectifies security vulnerabilities in your network and connected devices
- Qualys FreeScan service
  -  enables you to safely and accurately scan your network, servers, desktops and web apps for security threats and vulnerabilities. It is a free vulnerability scanner and network security tool for business networks. FreeScan is limited to ten (10) unique security scans of Internet accessible assets. It provides a detailed report that can be used to correct and fix security threats proactively
-  Nikto
   -   an Open Source (GPL) web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers
 - OpenVAS
   -  a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution.
- Retina CS 
  -  a vulnerability management software solution designed to provide organizations with context-aware vulnerability assessment and risk analysis. Retina’s result-oriented architecture works with users to proactively identify security exposures, analyze business impact, and plan and conduct remediation across disparate and heterogeneous infrastructure
- Microsoft Baseline Security Analyzer (MBSA)
  -  MBSA lets administrators scan local and remote systems for missing security updates as well as common security misconfigurations
- SecurityMetrics MobileScan
  -  complies with PCI SSC (Payment Card Industry Security Standards Council) guidelines to prevent mobile data theft
  
 # Notes 

- Trivial File Transfer Protocol (TFTP) 
  -  a File Transfer Protocol that allows a client to get a file from or put a file onto a remote host. 
  -  This protocol includes no login or access control mechanisms, and therefore it is recommended to take care when using this protocol for file transfers where authentication, access control, confidentiality, or integrity checking are needed. Otherwise, it may result in unauthorized access to remote host.
- The Netstat WMI scan
  -  finds open ports in the Windows system. 
- Silent dependencies 
  - limit the amount of plugin data.
-  According to Nessus Network Auditing, edited by Russ Rogers, ‘Consider unscanned ports as closed’ will tell Nessus that all other ports not included in the port range scan to be considered as closed. This prevents ports that are targeted against ports outside that range from running.”

- Buffer overflows
    - Buffer overflows are common software vulnerabilities that happen due to coding errors allowing attackers to get access to the target system. In a buffer overflow attack, attackers undermine the functioning of programs and try to take the control of the system by writing content beyond the allocated size of the buffer. Insufficient bounds checking in the program is the root cause because of which the buffer is not able to handle data beyond its limit, causing the flow of data to adjacent memory locations and overwriting their data values. Systems often crash or become unstable or show erratic program behavior when buffer overflow occurs.

- Active footprinting
  - Active footprinting involves gathering information about the target with direct interaction. In active footprinting, information is gathered by querying published name servers, extracting metadata, web spidering, Whois lookup, etc.

- Port scanning
  - Port scanning is the process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in. Port scanning involves connecting to or probing TCP and UDP ports on the target system to determine if the services are running or are in a listening state.

### assessment types


- Host-based assessments 
  -  a type of security check that involves carrying out a configuration-level check through the command line. These assessments check the security of a particular network or server. Host-based scanners assess systems to identify vulnerabilities such as incorrect registry and file permissions, as well as software configuration errors. Host-based assessment can use many commercial and open-source scanning tools.


- application assessment 
  - focuses on transactional Web applications, traditional client server applications, and hybrid systems. It analyzes all elements of an application infrastructure, including deployment and communication within the client and server. This type of assessment tests the web server infrastructure for any misconfiguration, outdated content, and known vulnerabilities. Security professionals use both commercial and open-source tools to perform such assessments.

- Passive Assessment
  - Passive assessments sniff the traffic present on the network to identify the active systems, network services, applications, and vulnerabilities. Passive assessments also provide a list of the users who are currently using the network.

- Active Assessment
  - Active assessments are a type of vulnerability assessment that uses network scanners to scan the network to identify the hosts, services, and vulnerabilities present in that network. Active network scanners have the capability to reduce the intrusiveness of the checks they perform.

- Wireless Network Assessments
  - Wireless network assessment determines the vulnerabilities in an organization’s wireless networks. Wireless network assessments try to attack wireless authentication mechanisms and get unauthorized access. This type of assessment tests wireless networks and identifies rogue wireless networks that may exist within an organization’s perimeter. These assessments audit client-specified sites with a wireless network.

### vulnerability management phases

- Creating Baseline
    - In this phase, critical assets are identified and prioritized to create a good baseline for the vulnerability management.

- Vulnerability Assessment
  - This is a very crucial phase in vulnerability management. In this step, the security analyst identifies the known vulnerabilities in the organization infrastructure.

- Risk Assessment
  - In this phase, all the serious uncertainties that are associated with the system are assessed, fixed, and permanently eliminated for ensuring a flaw free system.

- Remediation
  - Remediation is the process of reducing the severity of vulnerabilities. This phase is initiated after the successful implementation of the baseline and assessment steps.

- Verification
  - This phase provides a clear visibility into the firm and allows the security team to check whether all the previous phases are perfectly employed or not.

- Monitor
  - Regular monitoring needs to be performed for maintaining the system security using tools such as IDS/IPS, firewalls, etc.

### Assessment Tools
- Depth Assessment Tools
  - Depth assessment tools are used to find and identify previously unknown vulnerabilities in a system. Generally, these tools are used to identify vulnerabilities to an unstable degree of depth. Such types of tools include fuzzers that give arbitrary input to a system’s interface. Many of these tools use a set of vulnerability signatures for testing that the product is resistant to a known vulnerability or not.

- Scope Assessment Tools
  - Scope assessment tools provides assessment of the security by testing vulnerabilities in the applications and operating system. These tools provide a standard control and a reporting interface that allows the user to select a suitable scan.

- Application-Layer Vulnerability Assessment Tools
  - Application-layer vulnerability assessment tools are designed to serve the needs of all kinds of operating system types and applications.

- Active Scanning Tools
  - Active scanners perform vulnerability checks on the network that consume resources on the network.

### metrics
- CVSS assessment consists of three metrics for measuring vulnerabilities:
    - Base metrics: 
      - It represents the inherent qualities of a vulnerability. 
    - Temporal metrics: 
      - It represents the features that keep on changing during the lifetime of a vulnerability.
    - environmental metrics: 
      - It represents the vulnerabilities that are based on a particular environment or implementation.

### tools
- Nessus Professional 
    - is an assessment solution for identifying vulnerabilities, configuration issues, and malware that attackers use to penetrate networks. It performs vulnerability, configuration, and compliance assessment. It supports various technologies such as operating systems, network devices, hypervisors, databases, tablets/phones, web servers, and critical infrastructure. Nessus is the vulnerability scanning platform for auditors and security analysts. Users can schedule scans across multiple scanners, use wizards to easily and quickly create policies, schedule scans, and send results via email.

- Recon-ng and FOCA 
  - are footprinting tools used to collect basic information about the target systems in order to exploit them.

- Wireshark 
  - is a traffic capturing tool that lets you capture and interactively browse the traffic running on a computer network. It captures live network traffic from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI networks.

### vulnerability assessment report

- A vulnerability assessment report will provide detailed information on the vulnerabilities that are found in the computing environment. The report will help organizations to identify the security posture found in the computing systems (such as web servers, firewalls, routers, email, and file services) and provide solutions to reduce failures in the computing system.

- Vulnerability reports cover the following elements:

  -   Scan information: 
      -   This part of the report provides information such as the name of the scanning tool, its version, and the network ports that have to be scanned.

  - Target information: 
    - This part of the report contains information about the target system’s name and address.
  - Results: 
    - This section provides a complete scanning report. It contains subtopics such as target, services, vulnerability, classification, and assessment
  - Target:
    -  This subtopic includes each host’s detailed information.
  -  Services: 
     -   The subtopic defines the network services by their names and ports
   - Classification: 
     - This subtopic allows the system administrator to obtain additional information about the scanning such as origin of the scan.
   - Assessment:
     -  This class provides information regarding the scanner’s assessment of the vulnerability.
