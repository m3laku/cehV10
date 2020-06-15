
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