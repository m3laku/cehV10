## Information Sec OverView

### sending email with digital signature
        1. hash the message
        2. encryopt it wit the private key
        3. recipient has the digital certificate with the public key
        4. recipient can decrypt it and can see the hash and able to compare the hashes

### elements of Information Security
        1. confidentiality
        2. integrity // HASHING
        3. availability
        4. authenticity:
                - The major role of authentication is to confirm that a user is genuine, one who he / she claims to be
                - Controls such as biometrics, smart cards, and digital certificates ensure the authenticity of data
        5. non-repudation:
                 - the sender tcant deny that the message has been sent
                 - digital signature is used to provide non repudation


### Level of Security -- the confidentiality/usability/security triangle

## Information Security Threats and Attack Vectors

            Attacks = Motive + Method + Vulnerability

### TOP information security attack vectors

        1. cloud computing threats
        2. Advanced Persistant Threats: APT is an attack that is focused on stealing information from the victim machine without the user being aware of it. Slow in nature, the effect on computer performance is negligale
        3. viruses and worms: Viruses make their way into the computer when the attacker shares a malicious file containing it with the victim through the Internet, or through any removable media. Worms enter a network when the victim downloads a malicious file, opens a spam mail or browses a malicious website
        4. ransomware
        5. mobile threats
        6. botnet: A botnet is a huge network of compromised systems used by attackers to perform denial-of-service attacks. Bots, in a botnet, perform tasks such as uploading viruses, sending mails with botnets attached to them, stealing data, and so on. Antivirus programs might fail to find—or even scan for—spyware or botnets. Hence, it is essential to deploy programs specifically designed to find and eliminate such threats
        7. insider attack
        8. phising: Attackers perform phishing attacks by distributing malicious links via some communication channel
        9.  web application attacks: Majority of such attacks are the result of flawed coding and improper sanitization of input and output data from the web application
        10. IoT threats: The IoT devices connected to the Internet have little or no security that makes them vulnerable to various types of attacks. These devices include many software applications that are used to access the device remotely. Due to the hardware constraints such as memory, battery, etc. these IoT applications do not include complex security mechanisms to protect the devices from attacks. These drawbacks make the IoT devices more vulnerable and allow attackers to access the device remotely and perform various attack

### Information Security Threat Categories

        1. Network threats
        2. Host threats: Host threats target a particular system on which valuable information resides
        3. Application Threats
   
### Types of System Attacks
        1. Operating System attack
        2. Misconfiguration attacks
        3. Application level attacks, for example Session Hijacking:
                        Attackers may exploit session information in the vulnerable applications to perform session hijacking if the code implements a cookie less authentication. When the target tries to browse through a URL, the session or authentication token appears in the request URL instead of the secure cookie, to give access to the URL requested by the target.
        4. Shrink wrap code attacks

### Information WarFare

    Refers to the use of ICT to take competitive adantages
        - defensive information warfare
                    VS
        - offensive information warfare

    
    Information Warfare categories
        -  command and control (C2) warfare
        - Intelligence based warfare: Intelligence-based warfare is a sensor-based technology that directly corrupts technological systems
        - electronic warfare: use of radio electronic and chryptography techniques to degrade communication
        - psychological warfare
        - hacker warfare
        - economic warfare
        - cyber warfare

## Hacking concepts

### Hacking Phases
        1. Reconnaissance
        2. Scanning
              - pre attack phase
              - port scanner
              - extract information
              - The primary defense technique against port scanners is to shut down services that  are not required, as well as to implement appropriate port filtering.  
        3. Gaining Access: the attacker can gain access at 3 levels: operation system level, network level, application level
        4. Maintaining access: Rootkits gain access at the operating system level, while a Trojan horse gains access at the application level. Both rootkits and Trojans require users to install them locally. In Windows systems, most Trojans install themselves as a service and run as local system, with administrative access.
        5. Clearing tracks : it can be achieved by using tools such as PsTool, using steganography or tunelling(Tunneling takes advantage of the transmission protocol by carrying one protocol over another)

## Ethical hacking concepts

hacker vs cracker vs ethical hacker

### An ethical hacker’s evaluation of a client’s information system security seeks answers to three basic questions:  

1. What can an attacker see on the target system? 
2. What can an intruder do with that information? 
3. Are the attackers’ attempts being noticed on the target systems? 

## Information Security Controls

### information assurance -- IA
 - The integrity, availability, confidentiality and authenticity of information is protected during usage

 - it is accomplished with fisical, technical and administrative controls


### Information Security Management Program

 - Programs that are designed to enable a business to operate in a state of reduced risk.
 - It encompasses all organizational and operational processes, and participants relevant to information security

### Enterprise Information Security Architecture (EISA) 

 - EISA is a set of requirements, processes, principles, and models that determines the structure and behavior of an organization’s information system
 - The main objective of implementing EISA is to make sure that IT security is in alignment with business strategy. 

### Network Security Zoning

        1. internet zone
        2. internet DMZ
        3. production network zone - restricted zone, supports functions for which access should be limited.
        4. intranet - controlled zone
        5. management network zone - secured zone

### Defense in depth

- Defense-in-depth is a security strategy in which security professionals use several protection layers throughout an information system.

### information security policies

- Security policies are the foundation of the security infrastructure 
- Information security policy defines the basic security requirements and rules to be implemented in order to protect and secure organization’s information systems
-  Policies are not technology specific and accomplish three things:
   -   They reduce or eliminate legal liability of employees and third parties. 
   -    They protect confidential and proprietary information from theft, misuse, unauthorized disclosure, or modification.
   - They prevent wastage of the company’s computing resources.

- two types of policies: technical and administratice security policy
- types of policies:
  -  promiscuous
  -  permissive
  -  prudent 
  -  paranoid
  
- HR/Legal Implications of Security Policy Enforcement 

### Phisical security
- Physical security is the first layer of protection in any organization 
- It  involves protection of organizational assets from environmental and man made threats
- tpes of phisical security controls:
    -  preventive
    -  detective: act when preventive control fails
    -  deterrent
    -  corrective
    -  compensative // any of the security control can be phisical, technical or administrative

### Risk

- Risk refers to a degree of uncertainty or expectation that an adverse event may cause damage to the system 
- Risks are categorized into different levels according to their estimated impact on the system 
- A risk matrix is used to scale risk by considering the probability, likelihood, and consequence/impact of the risk
- Risk management is the process of reducing and maintaining risk at an acceptable level by means of a well-defined and actively employed security program

- risk management phases
  - identification
  - assessment
  - treatment
  - tracking
  - review

### Threat modelling
- Threat modeling is a risk assessment approach for analyzing security of an application by capturing, organizing, and analyzing all the information that affects the security of an application
  - identify security objectives
  - application overview
  - decompose application
  - Identify threats
  - identify vulnerabilities

-  Every application should have a threat model developed and documented, and should be revisited as the application evolves and development progresses.

### incident management
- Incident management is a set of defined processes to identify, analyze, prioritize, and resolve security incidents to restore normal service operations as quickly as possible and prevent future recurrence of the incident
- incident management process
  - preparation for incident handling and response
  - detection and analysis
  - classification and priorization
  - notification
  - containment
  - forensic investigation
  - eradiction and recovery
  - post incident activities

### security incident and event management (SIEM)

- SIEM performs real-time SOC (Security Operations Center) functions like identifying, monitoring, recording, auditing, and analyzing security incidents
- It provides security by tracking suspicious end-user behavior activities within a real-time IT environment
- It provides security management services combining Security Information Management (SIM), and Security Event Management (SEM)
   - SIM supports permanent storage, analysis and reporting of log data
   - SEM deals with real-time monitoring, correlation of events, notifications, and console views
- SIEM protects organization’s IT assets from data breaches occurred due to internal and external threats
-  SIEM applies normalization and aggregation to event data and contextual data collected from different internal and external sources
      -  input: evant data and contextual data => SIEM aggregates data => output reports, dash boards, real time monitoring, etc.

### User Behaviour Analysis UBA
- UBA technologies are designed to identify variations in traffic patterns caused by user behaviors which can be either disgruntled employees or malicious attackers
- It provides advanced threat detection in an organization to monitor specific behavioral characteristics of the employees
- UBA technologies are designed to identify variations in traffic patterns caused by user behaviors which can be either disgruntled employees or malicious attacker

### Network Security Controls

- Network security controls are used to ensure the confidentiality, integrity, and availability of the network services 
- either technical or administrative
- network sec controls include:
  -  Access Control:
     -  Access control is the selective restriction of access to a place or other system/network resource 
     -  It protects information assets by determining who can and cannot access them 
     -  It involves user identification, authentication, authorization, and accountability
     -  terminology: subject/object/ReferenceMonitor/operation
     -  two types: phisical and logical(accessing the network and data)
     -  three types of access control:
        -  Mandatory Access Control
        -  Discretionary Access Control
        -  RoleBased Access control
  -  Identification -- Example: Username, Account Number
  -  Authentication -- example: password, pin
  -  Authorization -- A user can only read the file but not write to or delete it.
  -  Accounting
  -  Cryptography
  -  Security Policy
- The overlapping use of these controls ensures defense in depth network security

### Identity and Access Management
- Identity and Access Management (IAM) is a framework that consists of users, procedures, and software products to manage user digital identities and access to resources of an organization 
- It ensures that “the right users obtain access to the right information at the right time” 
- The services provided by IAM are classified into four distinct components:
   -  Authentication 
   -  Authorization 
   -  User Management 
   -  Enterprise Directory Services (Central User Repository)
- 2 modules:
  - access management
  - identity management

### data leakage
- Data leakage refers to unauthorized access or disclosure of sensitive or confidential data
- Data leakage may happen electronically through an email or malicious link or via some physical method such as device theft, hacker break-ins, etc.
- insider threats VS external threats
- Data Loss Prevention: 
  - Data Loss Prevention (DLP) refers to the identification and monitoring of sensitive data to ensure that end users do not send sensitive information outside the corporate network

### Data Backup
- methods: HOT Backup vs COLD Backup vs WARM backup
- backup location: onSite VS offSite VS Cloud
- types: full/incremental/differentail(combination of previous two)

### role of AI in cyber security


- Machine learning (ML) and artificial intelligence (AI) are now vastly used across various industries and applications due to the increase in the computing power, data collection and storage capabilities 
- Machine Learning (ML) is unsupervised self-learning system that is used to define what the normal network looks like along with its devices and then use this to backtrack and report any deviations and anomalies in real time 
- AI and ML in cyber security helps in identifying new exploits and weaknesses which can be easily analyzed to mitigate further attacks

# Notes

### types of threats

Network Threats: A network is the collection of computers and other hardware connected by communication channels to share resources and information. As the information travels from one system to the other through the communication channel, a malicious person might break into the communication channel and steal the information traveling over the network.
Listed below are some of the network threats:

Information gathering
Sniffing and eavesdropping
Spoofing
Session hijacking
Man-in-the-Middle attack
Host Threats: Host threats target a particular system on which valuable information resides. Attackers try to breach the security of the information system resource.
Listed below are some of the host threats:

Malware attacks
Footprinting
Denial-of-Service attacks
Arbitrary code execution
Unauthorized access
 Application Threats: Applications can be vulnerable if proper security measures are not taken while developing, deploying, and maintaining them. Attackers exploit the vulnerabilities present in an application to steal or destroy data.
Listed below are some of the application threats:

Improper data/input validation
Authentication and authorization attacks
Security misconfiguration
Improper error handling and exception management
Information disclosure
Hidden-field manipulation
Broken session management
Buffer overflow issues

### Attacks

Dumpster Diving: Dumpster diving is the process of retrieving sensitive personal or organizational information by searching through trash bins.

Phishing: Phishing is a technique in which an attacker sends an email or provides a link falsely claiming to be from a legitimate site in an attempt to acquire a user’s personal or account information. The attacker registers a fake domain name, builds a lookalike website, and then mails the fake website’s link to several users. When a user clicks on the email link, it redirects him/her to the fake webpage, where he/she is lured to share sensitive details such as address and credit card information without knowing that it is a phishing site.

Piggybacking: Piggybacking usually implies entry into the building or security area with the consent of the authorized person. For example, attackers would request an authorized person to unlock a security door, saying that they have forgotten their ID badge. In the interest of common courtesy, the authorized person will allow the attacker to pass through the door.

Vishing: Vishing (voice or VoIP phishing) is an impersonation technique in which attacker uses Voice over IP (VoIP) technology to trick individuals into revealing their critical financial and personal information and uses the information for his/her financial gain.

### information warfare

Electronic warfare: Electronic warfare uses radio electronic and cryptographic techniques to degrade communication. Radio electronic techniques attack the physical means of sending information, whereas cryptographic techniques use bits and bytes to disrupt the means of sending information.

Intelligence-based warfare: Intelligence-based warfare is a sensor-based technology that directly corrupts technological systems. Intelligence-based warfare is a warfare that consists of the design, protection, and denial of systems that seek sufficient knowledge to dominate the battlespace.

Command and control warfare (C2 warfare): In the computer security industry, C2 warfare refers to the impact an attacker possesses over a compromised system or network that they control.

Economic warfare: Economic information warfare can affect the economy of a business or nation by blocking the flow of information. This could be especially devastating to organizations that do a lot of business in the digital world.

### hardening

The goal of hardening is to eliminate as many risks and threats to a computer system as necessary. Some of the hardening activities for a computer system can include the following: keeping security patches and hotfixes updated, monitoring security bulletins that apply to a system’s operating system and applications, installing a firewall, closing specific ports such as server ports, not allowing file sharing among programs, and so on.

### CC

Common Criteria (CC) is an international set of guidelines and specifications developed for evaluating information security products, specifically to ensure that they meet an agreed-upon security standard for government deployment.

### network access control

Network access control (also known as network administration control) deals with restricting the availability of a network to the end user depending on the security policy. It mainly restricts systems without antivirus, intrusion prevention software from accessing the network. NAC allows you to create policies for each user or systems and define policies for networks in terms of IP addresses.
NAC performs the following actions:
?        Evaluates unauthorized users, devices, or behaviors in the network. It provides access to authorized users and other entities.
?        It helps in identifying users and devices on a network. It also determines whether these users and devices are secure or not.
?        Examines the system integration with the network according to the security policies of the organization.
In this environment, there are a lot of outside devices coming in and out of the company with no controls. If we implement NAC we can say who can get into the network and what policies they need to comply with.

### ethical hacking

Ethical hacking is necessary as it allows countering attacks from malicious hackers by anticipating methods used by them to break into a system. Ethical hacking helps to predict the various possible vulnerabilities well in advance and rectify them without inciting any attack from outsiders. As hacking involves creative thinking, vulnerability testing and security audits cannot guarantee that the network is secure. Organizations need to implement a "defense-in-depth" strategy and perform penetration testing of their networks to estimate and expose vulnerabilities.


  




   


    

   

