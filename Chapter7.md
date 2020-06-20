# Malware Concepts
- Malware is a malicious software that damages or disables computer systems and gives limited or full control of the systems to the malware creator for the purpose of theft or fraud

### Components of a malware
     Components of a malware software relies on the requirements of the malware author who designs it for a specific target to perform the intended tasks
-  Crypter: 
    - Refers to a software program that can conceal the existence of malware. 
- Downloader:
    - Type of Trojan that downloads other malware (or) malicious code and files from the Internet on to the PC or device
-  Dropper: 
    - Attackers need to install the malware program or code on the system to make it run, and this program can do the installation task covertly
-  Exploit: 
    - Part of the malware that contains code or sequence of commands that can take advantage of a bug or vulnerability in a digital system or device.
- Injector: 
    - This program injects the exploits or malicious code available in the malware into other vulnerable running processes and changes the way of execution to hide or prevent its removal
- Obfuscator: 
    - A program to conceal the malicious code of malware via various techniques, thus making it hard for security mechanisms to detect or remove it.
- Packer: 
    - This software compresses the malware file to convert the code and data of malware into an unreadable format
-  Payload: 
    - Part of the malware that performs desired activity when activated
- Malicious Code: 
    - This is a piece of code that defines the basic functionality of the malware and comprises commands that result in security breaches

# Trojan concepts

- It is a program in which the malicious or harmful code is contained inside apparently harmless programming or data in such a way that it can get control and cause damage, such as ruining the file allocation table on your hard disk
- Trojans get activated upon users’ certain predefined actions and upon activation
- Indications of a Trojan attack include abnormal system and network activities
- Trojans create a covert communication channel between the victim computer and the attacker for transferring sensitive data
### Trojan Horse construction kits
- Trojan Horse construction kits help attackers to construct Trojan horses of their choice 
- tools
    - DarkHorse Trojan Virus Maker
        - creates user-specified Trojans by selecting from various options
### Wrappers
- A wrapper binds a Trojan executablewith genuine looking .EXE applications such as games or office applications 
- When the user runs the wrapped .EXE, it first installs the Trojan in the background and then runs the wrapping application in the foreground 
-  A wrapper encapsulates several components into a single data source to make it usable in a more convenient fashion than the original unwrapped source. 

### crypters
- Crypter is a software which is used by hackers to hide viruses, keyloggers or tools in any kind of file so that they do not easily get detected by antiviruses

### exploit kits
- An exploit kit or crimeware toolkit is a platform to deliver exploits and payloads such as Trojans, spywares, backdoors, bots, buffer overflow scripts, etc. on the target system

### types of trojans
1. remote access trojan
    - This Trojan works like a remote desktop access 
    - Hacker gains complete GUI access to the remote system
2. Backdoor trojan
    - A backdoor is a program which bypasses the system's customary security mechanisms to gain access to a restricted area of a computer system
    - Backdoors are used by the attacker to have uninterrupted access to the target machine 
3. Botnet trojans
    - uses IRC
    - Some of the botnet Trojans also have worm features and automatically spread to other systems in the network
    - Botnet Trojans infect a large number of computers across a large geographical area to create a network of bots that is controlled through a Command and Control (C&C) center 
    - Botnet is used to launch various attacks on a victim including denial-of-service attacks, spamming, click fraud, and the theft of financial information
4. Rootkit trojans
    - Rootkits are considered as powerful backdoors that specifically attack the root or operating system 
    - Compared to backdoors, rootkits cannot be detected by observing services, system task list or registries 
    - Rootkits consists of three components a dropper, loader, and the rootkit itself
5. E-Banking trojans
    - E-banking Trojans intercept a victim's account information before it is encrypted and sends it to the attacker's Trojan command and control center
    - The banking Trojan analysis includes:
        - Tan Gabber: 
            - A Transaction Authentication Number (TAN) is a single-use password for authenticating the online banking transaction. Banking Trojans intercept valid TAN entered by a user and replace it with a random number. The Bank will reject this invalid random number. An attacker after that misuses the intercepted TAN with the target’s login details.
        - HTML Injection: 
            - Trojan creates fake form fields on e-banking pages
        - Form Grabber:
            - Form Grabber is a type of malware that captures a target’s sensitive data such as IDs, passwords, and so on from a web browser form or page
        - Covert Credential Grabber: 
            - This type of malware stays dormant until the user performs an online financial transaction
6. Proxy Server Trojans 
    - Trojan Proxy is usually a standalone application that allows remote attackers to use the victim’s computer as a proxy to connect to the Internet.
7. Covert Channel TRojans
    - Covert Channel Tunneling Tool (CCTT) Trojan presents various exploitation techniques, creating arbitrary data transfer channels in the data streams authorized by a network access control system
8. Defacement Trojans
    - Defacement Trojans, once spread over the system, can destroy or change the entire content present in a database. However, they are more dangerous when attackers target websites, as they physically change their underlying HTML format, resulting in the modification of their content
9. Service Protocol Trojans
    - These Trojans can take advantage of vulnerable service protocols like VNC, HTTP/ HTTPS, etc. 
    - A VNC Trojan
        - starts a VNC Server daemon in the infected system (victim) where attacker connects to the victim using any VNC viewer and this Trojan will be difficult to detect using anti-viruses
    - HTTP Trojans  
        - can bypass any firewall and work in the reverse way of a straight HTTP tunnel 
    - ICMP Trojans
10. mobile trojans
11. IoT trojans
12. Security Software Disabler Trojans
    - Security software disabler trojans stop the working of security programs such as firewall, IDS, etc. either by disabling them or killing the processes
    - These are entry Trojans which allow an attacker to perform the next level of attack on the targeted system
13. Destructive Trojans 
    - delete files, corrupt OS, format files and drives, and perform massive destruction that can crash operating systems
14. DDoS Trojans 
    - are intended to perform DDoS (Distributed Denial-of-Service) attacks on the target machines, networks, or web address
15. Command shell Trojan 
    - gives remote control of a command shell on a victim’s machine

# Virus and Worm concepts 

- A virus is a self-replicating program that produces its own copy by attaching itself to another program, computer boot sector or document
-  For any virus to corrupt a system, it has to first associate its code with executable code.
- viruses can infect outside machines only with the assistance of computer users
- Following mentioned are the six stages of virus life from its origin to elimination.
     1. Design: Developing virus code using programming languages or construction kits. 
     2. Replication: Virus replicates for a period within the target system and then spreads itself 
     3. Launch: It gets activated with the user performing specific actions such as running an infected program
    4. Detection: A virus is identified as threat infecting target systems 
    5. Incorporation: Antivirus software developers assimilate defenses against the virus
    6. Execute the damage routine: Users install antivirus updates and eliminate the virus threats
- working with viruses
    1. infection phase  
        - In the infection phase, the virus replicates itself and attaches to an .exe file in the system
    2. Attack phase
        - Viruses are programmed with trigger events to activate and corrupt system
- virus Hoaxes 
    - are false alarms claiming reports about a non-existing virus which may contain virus attachments
- Fake or rogue anti-virus 
    - a form of Internet fraud using malware. It appears and performs similarly to a real anti-virus program. Fake anti-virus software often displays as banner ads, pop-ups, email links, and in search engine results when searching for anti-virus software
- Ransomware
    - a type of a malware which restricts access to the computer system’s files and folders and demands an online ransom payment to the malware creator(s) in order to remove the restrictions
    - examples  
        - Locky 
            - is a dreadful data encrypting parasite that not only infects the computer system but also has the ability to corrupt data on unmapped network shares. This ransomware spreads as a malicious Word document named invoice J-[8 random numbers].doc that is attached to spam emails
            - This Ransomware uses RSA-2048 and AES-128 encryption algorithms to lock personal files, including audio, video, image files, documents
        - WannaCry 
            - targets corporate networks without the knowledge of the user by exploiting known vulnerabilities in Microsoft Windows. 
            - WannaCry spreads through an exposed, vulnerable SMB port instead of phishing or social engineering.
        - Petya –NotPetya 
            - The master boot record is infected to execute a payload that encrypts a hard drive’s file system table and stops Windows from booting. It can spread over the network using WMIC
### Types of viruses
   1. System or Boot Sector Virus 
   - The most common targets for a virus are the system sectors, which include the master boot record (MBR) and the DOS boot record system sectors. An OS executes codes in these areas while booting.
   - Boot sector virus moves MBR to another location on the hard disk and copies itself to the original location of the MBR
   - When the system boots, the virus code is executed first and then control is passed to original MBR
   - The boot sector virus moves MBR to another location on the hard disk and copies itself to the original location of MBR. When the system boots, first the virus code executes and then control passes to the original MBR.
   -  One way to deal with this virus is to avoid the use of the Windows OS and switch to Linux or Mac because Windows is more prone to these attacks. Linux and Macintosh have a built-in safeguard to protect against these viruses

   2. File Virus
   - File viruses insert their code into the original file and infect executable files
   - File viruses infect files which are executed or interpreted in the system such as COM, EXE, SYS, OVL, OBJ, PRG, MNU and BAT files
   - File viruses can be either direct-action (non-resident) or memory-resident
   -  These types of viruses tend to be found immediately. 

   3. Multipartite Virus
   - Multipartite viruses infect the system boot sector and the executable files at the same time
   4. Macro Virus 
   - Macro viruses infect files created by Microsoft Word or Excel
   - Macro viruses are somewhat less harmful than other viruses

   5. Cluster Virus
   - Cluster viruses modify directory table entries so that it points users or system processes to the virus code instead of the actual program
   - There is only one copy of the virus on the disk infecting all the programs in the computer system
   - it will launch itself first when any program on the computer system is started and then the control is passed to actual program


   6. Stealth Virus/Tunneling Virus
   - These viruses evade the anti-virus software by intercepting its requests to the operating system 
   7. Encryption Virus 
   - This type of virus uses simple encryption to encipher the code
   - The virus is encrypted with a different key for each infected file
   - AV scanner cannot directly detect these types of viruses using signature detection methods

   8. Sparse Infector Virus
   - Sparse infector virus infects only occasionally (e.g. every tenth program executed), or only files whose lengths fall within a narrow range
   - The sparse infector virus works with two approaches:
        - Replicates only occasionally
        - Decides which file to infect based on certain conditions

   9. Polymorphic Virus
   - Polymorphic code is a code that mutates while keeping the original algorithm intact
   - To enable polymorphic code, the virus has to have a polymorphic engine (also called mutating engine or mutation engine) 
   - A well-written polymorphic virus therefore has no parts that stay the same on each infection
   - 3 components
        - encrypted virus code
        -  decryptor routine
        - mutation engine

   10. Metamorphic Virus 
   - Metamorphic viruses are programmed in such a way that they rewrite themselves completely each time they infect a new executable file. Such viruses are sophisticated and use metamorphic engines for their execution. Metamorphic code reprograms itself. It is translated into temporary code (a new variant of the same virus but with a different code), and then converted back to the original code. This technique, in which the original algorithm remains intact, is used to avoid pattern recognition of anti-virus software. This technique is more effective in comparison to polymorphic code. 
   11. Overwriting File or Cavity Virus
   - Cavity Virus, also known as space filler virus which overwrites a part of the host file with a constant (usually nulls), without increasing the length of the file and preserving its functionality

   12. Companion Virus/Camouflage Virus 
   - A Companion virus creates a companion file for each executable file the virus infects
   - Therefore, a companion virus may save itself as notepad.com and every time a user executes notepad.exe (good program), the computer will load notepad.com (virus) and infect the system

   13. Shell Virus 
   - Virus code forms a shell around the target host program’s code, making itself the original program and host code as its sub-routine
   - Almost all boot program viruses are shell viruses 
   14. File Extension Virus 
   - File extension viruses change the extensions of files .TXT is safe as it indicates a pure text file
   - With extensions turned off, if someone sends you a file named BAD.TXT.VBS, you will only see BAD.TXT
   15. Add-on Virus 
   - Add-on viruses append their code to the host code without making any changes to the latter or relocate the host code to insert their own code at the beginning 
   16. Intrusive Virus
   -  overwrite the host code partly or completely with the viral code
   17. Direct Action or Transient Virus 
   18. Terminate and Stay Resident Virus (TSR) 
   19. FAT Virus 
   - A FAT virus is a computer virus which attacks the File Allocation Table (FAT)
   - A FAT virus destroys the index, making it impossible for a computer to locate files
   20. Logic Bomb Virus 
   - A logic bomb is a virus that is triggered by a response to an event, usually date, like christmas etc
   21. Web Scripting Virus
   - A web scripting virus is a type of computer security vulnerability through websites that breaches your web browser security
   - This allows the attackers to inject client-side scripting into the web page
   22. Email Virus
   - An e-mail virus is computer code sent to you as an e-mail attachment which, if activated, will cause some unexpected and unusually harmful effect such as destroying certain files on your hard disk

### worms

- Computer worms are malicious programs that replicate, execute, and spread across the network connections independently, consuming available computing resources without human interaction
- Attackers use worm payload to install backdoors in infected computers, which turns them into zombies and creates botnet; these botnets can be used to carry further cyber attacks
- How is a Worm Different from a Virus?
    - Worm Replicates on its own
    - Worm Spreads through the Infected Network
    - A worm spreads more rapidly than a virus.
    - Typically, a worm does not modify any stored programs. It only exploits the CPU and memory
    - uses IRC
# Malware analysis

- An anti-virus sensor system is a collection of computer software that detects and analyzes malicious code threats such as viruses, worms, and Trojans. They are used along with sheep dip computers.
- Malware analysis is a process of reverse engineering a specific piece of malware in order to determine the origin, functionality, and potential impact of a given type of malware
- types
    - static malware analysis
        - Also known as code analysis, involves going through the executable binary code without actually executing it to have a better understanding of the malware and its purpose
    - dynamic malware analysis
        - Also known as behavioral analysis, involves executing the malware code to know how it interacts with the host system and its impact on the system after it has been infected
- the procedural steps for malware analysis: 
    1. Preparing Testbed
        - Steps to prepare the testbed:
            1. Allocate a physical system for the analysis lab 
            2. Install Virtual machine (VMware, Hyper-V, etc.) on the system 
            3. Install guest OSs on the Virtual machine(s) 
            4. Isolate the system from the network by ensuring that the NIC card is in “host only” mode
            5. Simulate internet services using tools such as iNetSim 6: Disable the ‘shared folders’ and the ‘guest isolation’  
            7. Install malware analysis tools  
            8. Generate hash value of each OS and tool  
            9. Copy the malware over to the guest OS

    2. Static Analysis 
        - File fingerprinting
            - is a process of computing the hash value for a given binary code
            - You can use the computed hash value to uniquely identify the malware or periodically verify if any changes are made to the binary code during analysis 
        - Local and Online Malware Scanning
        - Performing Strings Search
            -  Searching through the strings can provide information about the basic functionality of any program
        - Identifying Packing/ Obfuscation Methods
        -  Finding the Portable Executables (PE) Information
            - PE format is the executable file format used on Windows operating systems
        - Analyze the metadata of PE files to get information such as time and date of compilation, functions imported and exported by the program, linked libraries, icons, menus, version info, strings, etc. that are embedded in resources 
        -  Identifying File Dependencies
            - finding out all the library functions may allow you to guess what the malware program can do 
        - Malware Disassembly
    3. Dynamic Analysis
        -  stages
            1. System Baselining 
                - Refers to taking a snapshot of the system at the time the malware analysis begins
                - The main purpose of system baselining is to identify significant changes from the baseline state
            2. Host Integrity Monitoring
                - Host integrity monitoring involves taking a snapshot of the system state using the same tools before and after the analysis to detect changes made to the entities residing on the system
        - Port Monitoring
            - Use port monitoring tools such as netstat, TCPView, etc. to scan for suspicious ports and look for any connection established to unknown or suspicious IP addresses
            - tools
                - NetStat
                    - It displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics
                    - syntax
                        - netstat 
                            - Used without parameters, netstat displays active TCP connections.
                        - netstat -a
                            -  Displays all active TCP connections and the TCP and UDP ports on which the computer is listening.
                        -  netstat -an
                            - displays all the active TCP connections as well as the TCP and UDP ports on which the computer is listening along with addresses and port numbers
                - tcpView
        - Process Monitoring 
        - Registry Monitoring
            - Windows registry stores OS and program configuration details, such as settings and options 
            - Malware uses the registry to perform harmful activity continuously by storing entries into the registry and ensuring that the malicious program runs whenever the computer or device boots automatically 
        - Windows Services Monitoring
            - Use Windows services monitoring tools such as Windows Service Manager (SrvMan) to trace malicious services initiated by the malware
            - Malware may also employ rootkit techniques to manipulate HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services registry keys to hide its processes 
        -  Startup Programs Monitoring
            - Malware can alter the system settings and add themselves to the startup menu to perform malicious activities whenever the system starts
            - Manually check or use startup monitoring tools like Autoruns for Windows and WinPatrol to detect suspicious startup programs and processes
        - Event Logs Monitoring/Analysis
        -  Installation Monitoring
        - Files and Folder Monitoring
            -  Use file and folder integrity checkers like Tripwire and Netwrix Auditor to detect changes in system files and folders
            - tools
                - sigwerif
                - Tripwire
        - Device Drivers Monitoring
            - Use device drivers monitoring tools such as DriverView to scan for suspicious device drivers and to verify if the device drivers are genuine and downloaded from the publisher’s original site
        - Network Traffic Monitoring/Analysis
            - Use network scanners and packet sniffers to monitor network traffic going to malicious remote addresses
        - DNS Monitoring/ Resolution
            - Use DNS monitoring tools such as DNSQuerySniffer to verify the DNS servers that the malware tries to connect to and identify the type of connection
        - API Calls Monitoring
-  Virus Detection Methods
    1. Scanning
    2. Integrity checking 
    3. Interception
    4. Code Emulation 
    5. Heuristic Analysis
        - This method helps in detecting new or unknown viruses that are usually variants of an already existing virus family
- ZeuS trojan analzsis
    -  A ZeuS trojan consists of three main .dll files packed in UPX format
        - Kernel32.dll
        - Advapi32.dll,
        - user32.dll
# Countermeasures






































