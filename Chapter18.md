  ### IoT technology components

- Sensing Technology:
  -  Sensors embedded in the devices sense a wide variety of information from their surroundings like temperature, gases, location, working of some industrial machine as well as sensing health data of a patient.
-  IoT Gateways: 
    -  Gateways are used to bridge the gap between the IoT device (internal network) and the end user (external network) and thus allowing them to connect and communicate with each other. The data collected by the sensors in IoT devices send the collected data to the concerned user or cloud through the gateway
  - Cloud Server/Data Storage: 
    - The collected data after travelling through the gateway arrives at the cloud, where it is stored and undergoes data analysis. The processed data is then transmitted to the user where he/she takes certain action based on the information received by him/her
  - Remote Control using Mobile App:
    -  The end user uses remote controls such as mobile phones, tabs, laptops, etc. installed with a mobile app to monitor, control, retrieve data, and take a specific action on IoT devices from a remote location.

### IoT architecture layers

- Edge Technology Layer
  - This layer consists of all the hardware parts like sensors, RFID tags, readers or other soft sensors and the device itself. These entities are the primary part of the data sensors that are deployed in the field for monitoring or sensing various phenomena. This layer plays an important part in data collection, connecting devices within the network and with the server.
- Access Gateway Layer
  - This layer helps to bridge the gap between two endpoints like a device and a client. The very first data handling also takes place in this layer. It carries out message routing, message identification and subscribing
- internet Layer
  - This is the crucial layer as it serves as the main component in carrying out the communication between two endpoints such as device-to-device, device-to-cloud, device-to-gateway and back-end data-sharing.
- Middleware Layer
  - This is one of the most critical layers that operates in two-way mode. As the name suggests this layer sits in the middle of the application layer and the hardware layer, thus behaving as an interface between these two layers. It is responsible for important functions such as data management, device management and various issues like data analysis, data aggregation, data filtering, device information discovery and access control.
- Application Layer
    - This layer placed at the top of the stack, is responsible for the delivery of services to the respective users from different sectors like building, industrial, manufacturing, automobile, security, healthcare, etc.

### Communication protocols

- ZigBee
  - short-range wireless communication
- LTE-Advanced 
  -  type of Medium-range Wireless Communication.
  -  standard for mobile communication that provides enhancement to LTE thus focusing on providing higher capacity in terms of data rate, extended range, efficiency and performance. 
- Very Small Aperture Terminal (VSAT) 
  -  type of long-range Wireless Communication.
- Power-line Communication (PLC)
  - type of Wires Communication.
- Near Field Communication (NFC)
  - uses magnetic field induction to enable communication between two electronic devices
- Multimedia over Coax Alliance (MoCA): 
  - MoCA is a type of network protocol that provides a high definition video of home and content related to it over existing coaxial cable. 
  - wired communication protocol. 
- HaLow: 
  - It is another variant of Wi-Fi standard that provides extended range, making it useful for communications in rural areas. It offers low data rates, thus reducing power and cost for transmission.
- Thread
  - IPv6 based networking protocol for IoT devices. Its main aim is home automation, so that the devices can communicate with each other on local wireless networks

### The protocols used in various communication models are listed below: 
- Device-to-Cloud Communication Model:
  -  Wi-Fi, 
  -  Ethernet,
  -   cellular. 
- Device-to-Gateway Communication Model: 
  - ZigBee
  -  Z-Wave. 
- Back-End Data-Sharing Communication Model: 
  - CoAP or HTTP.

### Communication Model
- Device-to-Device Communication Model: 
  - In this type of communication, devices that are connected interact with each other through the internet but mostly they use protocols like ZigBee, Z-Wave or Bluetooth. 
- Device-to-Cloud Communication Model:
  -  In this type of communication, devices communicate with the cloud directly rather than directly communicating with the client in order to send or receive the data or commands.
- Device-to-Gateway Communication Model: 
  - In the Device-to-Gateway communication, Internet of Things device communicates with an intermediate device called a Gateway, which in turn communicates with the cloud service.
- Back-End Data-Sharing Communication Model: 
  - This type of communication model extends the device-to-cloud communication type in which the data from the IoT devices can be accessed by authorized third parties. Here devices upload their data onto the cloud which is later accessed or analyzed by the third parties.

### IoT vulnerabilities

- Insufficient Authentication/Authorization: 
  - Insufficient authentication refers to using weak credentials such as an insecure or weak password which offers poor security, thus allowing a hacker to gain access to the user account, and causing loss of data, loss of accountability and denying user to access the account.
- Insecure Network Services: 
  - Insecure network services are prone to various attacks like buffer overflow attacks, attacks that cause denial-of-service scenario, thus leaving the device inaccessible to the user. An attacker uses various automated tools such as port scanners and fuzzers to detect the open ports and exploit them to gain unauthorized access to the services.
- Insecure Web Interface:
  -  Insecure web interface occurs when certain issues arise such as weak credentials, lack of account lockout mechanism and account enumeration. These issues result in loss of data, loss of privacy, lack of accountability, denial of access and complete device access takeover.
- Privacy Concerns: 
  - IoT devices generate some private and confidential data but due to lack of proper protection schemes, it leads to privacy concerns, which makes it is easy to discover and review the data that is being produced, sent, and collected.

### Attacks

- Rolling Code Attack: 
  - An attacker jams and sniffs the signal to obtain the code transferred to the vehicle’s receiver and uses it to unlock and steal the vehicle.
- Jamming Attack: 
  - An attacker jams the signal between the sender and the receiver with malicious traffic that makes the two endpoints unable to communicate with each other.
- DDoS Attack: 
  - An attacker converts the devices into an army of botnet to target a specific system or server, making it unavailable to provide services.
- BlueBorne Attack: 
  - BlueBorne attack is performed on Bluetooth connections to gain access and take full control of the target device. Attackers connect to nearby devices and exploit the vulnerabilities of the Bluetooth protocol to compromise the devices. BlueBorne is a collection of various techniques based on the known vulnerabilities of the Bluetooth protocol.
- Sybil Attack: An attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks.
- Replay Attack:
  -  Attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device.
- Side Channel Attack:
  -  Attackers perform side channel attacks by extracting information about encryption keys by observing the emission of signals i.e. "side channels" from IoT devices.
- Exploit Kits:
  -  Exploit kit is a malicious script used by the attackers to exploit poorly patched vulnerabilities in an IoT device. These kits are designed in such a way that whenever there are new vulnerabilities, new ways of exploitation and add on functions will be added to the device automatically.

### Codes
- Hex Code: 
  - A color hex code is a way of specifying color using hexadecimal values. The code itself is a hex triplet, which represents three separate values that specify the levels of the component colors. It is used by programmers to describe locations in memory because it can represent every byte.
- Unicode: 
  - It is a character coding system to support worldwide interchange, processing, and display of the written texts. This type of code is mostly used in evading IDS. 
- Rolling Code: 
  - the form of a code from a modern key fob that locks or unlocks the vehicle. Here a code is sent to the vehicle which is different for every other use and is only used once, that means if a vehicle receives a same code again it rejects it. This code which locks or unlocks a car or a garage is called as Rolling Code or Hopping Code. It is used in keyless entry system to prevent replay attacks. An eavesdropper can capture the code transmitted and later use it to unlock the garage or the vehicle. 
- Polymorphic Code: 
  - It is code that uses a polymorphic engine to mutate while keeping the original algorithm intact. Polymorphic code can be also used to generate encryption algorithms.
  
### Vulnerability scanning using Nmap
- Attackers use vulnerability-scanning tools such as Nmap to identify the IoT devices connected to the network along with their open ports and services. - - Nmap generates raw IP packets in different ways to identify live hosts or devices on the network, services offered by them, their operating systems, type of packet filters used, etc. 
- Attackers use the following Nmap command to scan a particular IP address:
  - nmap -n -Pn -sS -pT:0-65535 -v -A -oX <Name><IP>
- To perform complete scan of the IoT device that checks for both TCP and UDP services and ports:
  - nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>
- To identify the IPv6 capabilities of a device: 
  - nmap -6 -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>

### phases of IoT hacking

- Vulnerability Scanning: 
  - Once the attackers gather information about a target device, they search for the attack surfaces of a device (identify the vulnerabilities) which they can attack. Vulnerability scanning allows an attacker to find the total number of vulnerabilities present in the firmware, infrastructure and system components of an IoT device that is accessible. After identifying the attack surface area, the attacker will scan for vulnerabilities in that area to identify an attack vector and perform further exploitation on the device.
- Gain Access: 
  - Vulnerabilities identified in the vulnerability scanning phase allow an attacker to remotely gain access, command and control the attack while evading detection from various security products. Based on the vulnerabilities in an IoT device, the attacker may turn the device into a backdoor to gain access to an organization’s network without infecting any end system that is protected by IDS/IPS, firewall, antivirus software, etc.
- Information Gathering: 
  - The first and the foremost step in IoT device hacking is to extract information such as IP address, protocols used (Zigbee, BLE, 5G, IPv6LoWPAN, etc.), open ports, device type, Geo location of a device, manufacturing number and manufacturing company of a device. In this step, an attacker also identifies the hardware design, its infrastructure and the main components embedded on a target device that is present online.
- Launch Attacks:
  -  In vulnerability scanning phase, attackers try to find out the vulnerabilities present in the target device. The vulnerabilities found are then exploited further to launch various attacks such as DDoS attacks, rolling code attacks, jamming signal attacks, Sybil attacks, MITM attacks, data and identity theft attacks, etc. 

### Tools

- RFCrack: 
  - Attackers use the RFCrack tool to obtain the rolling code sent by the victim to unlock a vehicle and later use the same code for unlocking and stealing the vehicle. RFCrack is used for testing RF communications between any physical device that communicates over sub Ghz frequencies.
  - commands
    - Live Replay:
      - python RFCrack.py -i
    - Rolling Code: 
      - python RFCrack.py -r -M MOD_2FSK -F 314350000
    - Adjust RSSI Range:  p
      - python RFCrack.py -r -U "-75" -L "-5" -M MOD_2FSK -F 314350000
    - Jamming:
      - python RFCrack.py -j -F 314000000 
- Multiping:
  -  An attacker can use the MultiPing tool to find IP address of any IoT device in the target network. After obtaining the IP address of an IoT device, the attacker can perform further scanning to identify vulnerabilities present in that device.
- Foren6: 
  - Foren6 uses sniffers to capture 6LoWPAN traffic and renders the network state in a graphical user interface. It detects routing problems. The Routing Protocol for 6LoWPAN Networks, RPL, is an emerging IETF standard. Foren6 captures all RPL-related information and identifies abnormal behaviors. It combines multiple sniffers and captures live packets from deployed networks in a non-intrusive manner.
- Nmap:
  -  Attackers use vulnerability-scanning tools such as Nmap to identify the IoT devices connected to the network along with their open ports and services. Nmap generates raw IP packets in different ways to identify live hosts or devices on the network, services offered by them, their operating systems, type of packet filters used, etc.
- Zigbee Framework:
  -  Attify ZigBee framework consists of a set of tools used to perform ZigBee penetration testing. ZigBee protocol makes use of 16 different channels for all communications. Attackers use Zbstumbler from Attify Zigbee framework to identify the channel used by the target device.
- HackRF One:
  -  Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device. 
- RIoT Vulnerability Scanner:
  -  Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. Utilizing precise information such as server banner and header data, RIoT will pinpoint the make and model of a particular IoT device. 
- Firmware Mod Kit: 
  - Attackers remain undetected by clearing the logs, updating firmware and using malicious programs such as backdoor, Trojans, etc. to maintain access. Attackers use tools such as Firmware Mod Kit, Firmalyzer Enterprise, Firmware Analysis Toolkit, etc. to exploit firmware. The Firmware Mod Kit allows for easy deconstruction and reconstruction of firmware images for various embedded devices. 
- Z-Wave Sniffer:
  -  It is used to sniff traffic, perform real-time monitoring and capture packets from all Z-Wave networks. It is a hardware tool used to sniff traffic generated by smart devices connected in the network.
- Censys:
  -  Censys is a public search engine and data processing facility backed by data collected from ongoing Internet-wide scans. Censys supports full-text searches on protocol banners and queries a wide range of derived fields.
- Firmalyzer Enterprise: 
  - Firmalyzer enables device vendors and security professionals to perform automated security assessment on software that powers IoT devices (firmware) in order to identify configuration and application vulnerabilities. This tool notifies users about the vulnerabilities discovered and assists to mitigate those in a timely manner.
- beSTORM: 
  - beSTORM is a smart fuzzer to find buffer overflow vulnerabilities by automating and documenting the process of delivering corrupted input and watching for unexpected response from the application. It supports multi-protocol environment and address breaches by testing over 50 protocols while providing automated binary and textual analysis, advanced debugging and stack tracing. 
- DigiCert IoT Security Solution:
  -  DigiCert Home and Consumer IoT Security Solutions protect private data and home networks while preventing unauthorized access using PKI-based security solutions for consumer IoT devices.
- SeaCat.io:
  -  SeaCat.io is a security-first SaaS technology to operate IoT products in a reliable, scalable and secure manner. It provides protection to end users, business, and data.
- Censys:
  -  Censys is a public search engine and data processing facility backed by data collected from ongoing Internet-wide scans. Censys supports full-text searches on protocol banners and queries a wide range of derived fields.
- Firmalyzer Enterprise: 
  - Firmalyzer enables device vendors and security professionals to perform automated security assessment on software that powers IoT devices (firmware) in order to identify configuration and application vulnerabilities. This tool notifies users about the vulnerabilities discovered and assists to mitigate those in a timely manner. 

# countermeasures

- Insecure Web Interface
  - Enable default credentials to be changed
  - Enable account lockout mechanism
  - Conduct periodic assessment of web applications
- Insufficient Authentication / Authorization
  - Implement secure password recovery mechanisms
  - Use strong and complex passwords
  - Enable two-factor authentication
- Insecure Network Services
  - Close open network ports
  - Disable UPnP
  - Review network services for vulnerabilities
- Lack of Transport Encryption / Integrity Verification
  - Encrypt communication between endpoints
  - Maintain SSL/TLS implementations
  - Not to use proprietary encryption solutions

### Ports
- Port 23: 
  - TCP port 23 is used for Telnet Services.
- Port 48101: 
  - TCP/UDP port 48101 is used by the infected devices to spread malicious files to the other devices in the network. Monitor traffic on port 48101 as the infected devices attempt to spread the malicious file using port 48101
- Port 22: 
  - TCP port 22 is used for SSH services.
- Port 53: 
  - TCP/UDP port 53 is used for DNS services.

### security considerations

- Mobile: 
  - An ideal framework for the mobile interface should include proper authentication mechanism for the user, account lockout mechanism after a certain number of failed attempts, local storage security, encrypted communication channels and the security of the data transmitted over the channel.
- Gateway:
  -  An ideal framework for the gateway should incorporate strong encryption techniques for secure communications between endpoints. Also, the authentication mechanism for the edge components should be as strong as any other component in the framework. Where ever possible the gateway should be designed in such a way that it authenticates multi-directionally to carry out trusted communication between the edge and the cloud. Automatic updates should also be provided to the device for countering vulnerabilities.
- Cloud Platform:
  -  A secure framework for the cloud component should include encrypted communications, strong authentication credentials, secure web interface, encrypted storage, automatic updates and so on.
- Edge:
  -  Framework consideration for edge would be proper communications and storage encryption, no default credentials, strong passwords, use latest up to date components and so on.
  
  