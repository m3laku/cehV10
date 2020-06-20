# System Hacking Concepts

### CEH Hacking Methodology

- footprinting
- scanning 
- enumeration
- vulnerability analysis
- system hacking
    - gaining access
        - cracking passwords
        - escalation priviledged
    - maintainig access
        - executing applications
        - hiding files
    - clearing logs
        -  covering tracks

# Cracking passwords

### Types of password attacks
- non electronic
    - dumpster diving
    - shoulder surfing
    - keyboard sniffing
    - social engineering
- active online
    - dictionary attacks
        - A dictionary file is loaded into the cracking application that runs against user accounts
        - dictionary attacks do not work in systems using passphrases
        - Methods to improve the success of a dictionary attack:
            - Use of a number of different dictionaries, such as Technical and foreign dictionaries, which increases the number of possibilities
            - Use of string manipulation with the dictionary (e.g., if the dictionary contains the word “system,” string manipulation creates anagrams like “metsys,” among others)

    - brute forcing attack
        - Cryptanalysis is a brute-force attack on an encryption employing a search of the keyspace.
    - rule based attack
        - This attack is used when the attacker gets some information about the password
        - more powerful attack than the dictionary and brute-force attacks, because the cracker knows the password type
        - hybrid attack
        - combimation of brute force and dictionary attack
        - Syllable Attack
            - Hackers use this cracking technique when passwords are not known words. Attackers use the dictionary and other methods to crack them, as well as all possible combinations of them

    - password guessing
        - steps
            - Find a valid user 
            - Create a list of possible passwords 
            - Rank passwords from high probability to low 
            - Key in each password, until correct password is discovered
        -  Manual Password-Cracking Algorithm
            - using for loop
    - trojan/spyware/keylogger
    - hash injection atack 
        - A hash injection attack allows an attacker to inject a compromised hash into a local session and use the hash to validate network resources
        - The attacker finds and extracts a logged on domain admin account hash
        - The attacker uses the extracted hash to log on to the domain controller
    - LLMNR and NBT-NS poisoning
        - two main elements of Windows operating systems used to perform name resolution for hosts present on the same link
        - The attacker cracks the NTLMv2 hash obtained from the victim’s authentication process 
        - The extracted credentials are used to log on to the host system in the network
        - to defend against it: 
            - disable  them

- passive online 
    - wire sniffing
        - gather packet at DataLink Layer
    - man in the middle
    - replay attack
        - In a replay attack, packets and authentication tokens are captured using a sniffer. After the relevant info is extracted, the tokens are placed back on the network to gain access
       

- offline
    - rainbow table attack
        - A rainbow table is a precomputed table which contains word lists like dictionary files and brute force lists and their hash values
    - distributed network attack
        - A Distributed Network Attack (DNA) technique is used for recovering passwords from hashes or password protected files using the unused processing power of machines across the network to decrypt passwords
        - 2 modules:    
            - server interface
            - client interafce

### Microsoft Authentication

- Windows password hashes are not salted
- When users log in to a Windows computer, a series of steps is performed for user authentication. The Windows operating system authenticates its users with the help of three mechansims (protocols) provided by Microsoft:

    - SAM database
        - Windows stores user passwords in SAM, or in the Active Directory database in domains. Passwords are never stored in clear text; passwords are hashed and the results are stored in the SAM
        - It is not possible to copy the SAM file to another location in the case of online attacks
        - %SystemRoot%/system32/config/SAM
        - the LM hash value is set to a “dummy” value when a user or administrator sets a password of more than 14 characters.

    - NTLM Authentication
        - default authentication scheme that performs authentication using a challenge/response strategy. Because it does not rely on any official protocol specification, there is no guarantee that it works correctly in every situation.  NTLM authentication consists of two protocols: NTLM authentication protocol and LM authentication protocol. These protocols use different hash methodology to store users’ passwords in the SAM database.
            - NTLM authentication protocol
            - LM authentication protocol
        - In NTLM authentication, the client and server negotiate an authentication protocol. This is accomplished through the Microsoft negotiated Security Support Provider (SSP).

    - kerberos authentiaction - AIO book!!!
        - Microsoft has upgraded its default authentication protocol to Kerberos which provides a stronger authentication for client/server applications than NTLM
        - using secret-key cryptography
        - provides a mutual authentication. Both the server and the user verify each other’s identity. 
        - Messages sent through the Kerberos protocol are protected against replay attacks and eavesdropping

# Escalating priviledges

- Escalating privileges is the second stage of system hacking
    - Attacker performs privilege escalation attack which takes advantage of design flaws, programming errors, bugs, and configuration oversights in the OS and software application to gain administrative access to the network and its associated applications
- types
    - horizontal
    - vertical

### techniques

- Privilege Escalation Using DLL Hijacking
    - Most Windows applications do not use the fully qualified path when loading an external DLL library instead they search directory from which they have been loaded first
    - If attackers can place a malicious DLL in the application directory, it will be executed in place of the real DLL
- Privilege Escalation by Exploiting Vulnerabilities
    - Attackers exploit software vulnerabilities by taking advantage of programming flaws in a program, service, or within the operating system software or kernel to execute malicious code
- Privilege Escalation Using Dylib Hijacking -- OS X
    - In OS X, applications while loading an external dylib (dynamic library), the loader searches for dylib in multiple directories
    - If attackers can inject a malicious dylib in one of the primary directories, it will be executed in place of the original dylib
- Privilege Escalation Using Spectre and Meltdown Vulnerabilities
    - Spectre and Meltdown are vulnerabilities found in the design of the modern processor chips from AMD, ARM, and Intel
    - Spectre Vulnerability
        - Attackers may take advantage of this vulnerability to read adjacent memory locations of a process and access information for which he/she is not authorized
        - Using this vulnerability an attacker can even read the kernel memory or perform a web based attack using JavaScript
         - The processor is forced to accomplish a speculative execution of a read before bounds checking is performed. As a result, an attacker can access and read out of bound memory locations.
    - Meltdown Vulnerability
        - apple specific
        - Attackers may take advantage of this vulnerability to escalate privileges by forcing an unprivileged process to read other adjacent memory locations such as kernel memory and physical memory
        - This leads to revealing of critical system information such as credentials, private keys, etc.
- Access Token Manipulation
    - Windows operating system uses access tokens to determine the security context of a process or thread 
    - Attackers can obtain access tokens of other users or generate spoofed tokens to escalate privileges and perform malicious activities by evading detection
- Application Shimming
    - Windows Application Compatibility Framework, shim is used to provide compatibility between the older and newer versions of Windows operating system 
    - Shims like RedirectEXE, injectDLL, and GetProcAddress can be used by attackers to escalate privileges, install backdoors, disable Windows defender, etc.
- File System Permissions Weakness
    - If the file system permissions of binaries are not properly set, an attacker can replace the target binary with a malicious file 
    - If the process that is executing this binary is having higher level permissions then the malicious binary also executes under higher level permissions
- Path Interception
    - Applications include many weaknesses and misconfigurations like unquoted paths, path environment variable misconfiguration, and search order hijacking that lead to path interception Path interception helps an attacker to maintain persistence on a system and escalate privileges
- Scheduled Task
    - Windows Task Scheduler along with utilities such as ‘at’ and ‘schtasks’ can be used to schedule programs that can be executed at a specific date and time 
    - Attacker can use this technique to execute malicious programs at system startup, maintain persistence, perform remote execution, escalate privileges, etc.
- Launch Daemon
    - Launchd is used in MacOS and OS X boot up to complete the system initialization process by loading parameters for each launch-on-demand system-level daemon 
    - Daemons have plists that are linked to executables that run at start up Attacker can alter the launch daemon’s executable to maintain persistence or to escalate privileges
- Plist Modification
    - Plist files in MacOS and OS X describe when programs should execute, executable file path, program parameters, required OS permissions, etc. - Attackers alter plist files to execute malicious code on behalf of a legitimate user to escalate privileges
- Setuid and Setgid
    - In Linux and MacOS, if an application uses setuid or setgid then the application will execute with the privileges of the owning user or group 
    - An attacker can exploit the applications with the setuid or setgid flags to execute malicious code with elevated privileges
- Web Shell
    - A Web shell is a web-based script that allows access to a web server
    - Attackers create web shells to inject malicious script on a web server to maintain persistent access and escalate privilege

# Executing applications

- Attackers execute malicious applications in this stage in a process called “owning” the system. 
- The malicious programs attackers execute on target systems can be: 
    - Backdoors
        - Program designed to deny or disrupt operation, gather information that leads to exploitation or loss of privacy, gain unauthorized access to system resources.
    - Crackers-
        - Piece of software or program designed for cracking a code or passwords.
    -  Keyloggers
        - This can be hardware or a software type. In either case, the objective is to record each keystroke made on the computer keyboard.
        - Keystroke loggers are programs or hardware devices that monitor each keystroke as user types on a keyboard, logs onto a file, or transmits them to a remote location
    - Spyware
        - Spy software may capture the screenshots and send them to a specified location defined by the hacker. To this purpose, attackers have to maintain access to victims’ computers. After deriving all the requisite information from the victim’s computer, the attacker installs several backdoors to maintain easy access to it in the future
        - spyware propagation
            - Drive-by download
            - Masquerading as anti-spyware 
            - Web browser vulnerability exploits
            - Piggybacked software installation 
            - Browser add-ons
            - Cookies 
        - types
            - desktop spyware
            - email spyware
            - internet spyware
            - child monitoring spyware
            - screen capturing
            - usb spyware
            - audio
            - video
            - print spyware
            - telephone spyware
            - gps spyware

# Hiding files 

### Rootkits

-  To defend against rootkits, use integrity checking programs for critical system files.
- attacker requires administrator access to the target system
- Rootkits are programs that hide their presence as well as attacker’s malicious activities, granting them full access to the server or host at that time and also in future
- Rootkits replace certain operating system calls and utilities with its own modified versions of those routines that in turn undermine the security of the target system causing malicious functions to be executed
-  A typical rootkit comprises backdoor programs, DDoS programs, packet sniffers, log-wiping utilities, IRC bots, and others. 
- Objectives of rootkit: 
    - To root the host system and gain remote backdoor access 
    - To mask attacker tracks and presence of malicious applications or processes
    - To gather sensitive data, network traffic, etc. from the system to which attackers might be restricted or possess no access
    - To store other malicious programs on the system and act as a server resource for bot updates
- Types
    - Hypervisor Level Rootkit
        -Acts as a hypervisor and modifies the boot sequence of the computer system to load the host operating system as a virtual machine
    - Hardware/Firmware Rootkit
        - Hides in hardware devices or platform firmware which is not inspected for code integrity
    - Kernel Level Rootkit
        - The kernel is the core of the operating system. Kernel level rootkit runs in Ring-0 with highest operating system privileges
        - Adds malicious code or replaces original OS kernel and device driver codes
    - Boot Loader Level Rootkit
        - Replaces the original boot loader with one controlled by a remote attacker
    - application level rootkit
        - Replaces regular application binaries with fake Trojan or modifies the behavior of existing applications by injecting malicious code
    - Library Level Rootkits
        - Replaces original system calls with fake ones to hide information about the attacker
        - Library level rootkits work higher up in the OS and they usually patch, hook, or supplant system calls with backdoor versions to keep the attacker unknown
- how rootkits work
    - System hooking is a process of changing and replacing the original function pointer with the pointer provided by the rootkit in stealth mode
- detecting rootkits
    - Integrity based detection
        - can be regarded as a substitute to both signatures and heuristics based detection. Initially, the user runs tools such as Tripware, AIDE, etc. on a clean system. These tools create a baseline of clean system files and store them in a database. Integrity-based detection functions by comparing a current file system, boot records, or memory snapshot with that trusted baseline.
    - Signature-based detection
        - work as a rootkit fingerprint. It compares characteristics of all system processes and executable files with a database of known rootkit fingerprints.
    - Heuristic detection 
        - works by identifying deviations in normal operating system patterns or behaviors. This kind of detection is also known as behavioral detection. 
    - The Runtime Execution Path Profiling technique
        -  compares runtime execution path profiling of all system processes and executable files.

- steps for detecting rootkits
    -  by examining file system 
        1. Run "dir /s /b /ah" and "dir /s /b /a-h" inside the potentially infected OS and save the results
        2. Boot into a clean CD, run "dir /s /b /ah" and "dir /s /b /a-h" on the same drive and save the results
        3. Run a clean version of WinDiff on the two sets of results to detect file-hiding ghostware (i.e., invisible inside, but visible from outside)
    -  examining the registry
         1. Run regedit.exe from inside the potentially infected operating system.
        2. Export HKEY_LOCAL_MACHINE\SOFTWARE and HKEY_LOCAL_MACHINE\SYSTEM hives in text file format.
        3. Boot into a clean CD (such as WinPE). 4. Run regedit.exe.

### NTFS Data Stream

- NTFS Alternate Data Stream (ADS) is a Windows hidden stream which contains metadata for the file such as attributes, word count, author name and access, and modification time of the files
- ADS is the ability to fork data into existing files without changing or altering their functionality, size, or display to file browsing utilities
- alternate data streams are not present in the file, but attached to it through the file table
- ADS allows an attacker to inject malicious code in files on an accessible system and execute them without being detected by the user
-  Files with ADS are impossible to detect using native file browsing techniques like the command line or Windows Explorer
- to launch
    - c:\>notepad myfile.txt:lion.txt 
- PAGE 610
- How to Defend against NTFS Streams 
    - To delete hidden NTFS streams, move the suspected files to FAT partition 
    - Use third-party file integrity checker such as Tripwire File Integrity Monitor to maintain integrity of NTFS partition files against unauthorized ADS

### Steganography

- See AIO notes!!!
- types
    - technical
        -  hides a message using scientific methods
        - examples
            - invisible ink
            - microdot: 
                - is text or an image considerably condensed in size (with the help of a reverse microscope), up to one page in a single dot, to avoid detection by unintended recipients. Microdots are usually circular, about one millimeter in diameter, but are changeable into different shapes and sizes.
            - computer based

    - linguistic
        -  hides it in a carrier
        - examples
            - Semagrams 
                - involve the steganography technique that hides information with the help of signs or symbols
            - Open code 
                - hides the secret message in a legitimate carrier message specifically designed in a pattern on a document that is unclear to the average reader
- types based on cover medium
    - Whitespace Steganography:
        - In white space steganography, the user hides the messages in ASCII text by adding white spaces to the end of the lines.
    - image steganography, 
        - the information is hidden in image files of different formats such as .PNG, .JPG, .BMP, etc.
        - techniques
            - Least Significant Bit Insertion 
            - Algorithms and Transformation 
    - Document Steganography 
        - technique of hiding secret messages transferred in the form of documents. It includes addition of whitespaces and tabs at the end of the lines
    - Folder steganography
        - Files are hidden and encrypted within a folder and do not appear to normal Windows applications, including Windows Explorer
    - Spam/email steganography
        - refers to the technique of sending secret messages by hiding them in spam/email messages
- Steganalysis  
    - the art of discovering and rendering covert messages using steganograph
    - PAGE 641
# Covering tracks

- Disabling Auditing: Auditpol
    - Intruders will disable auditing immediately after gaining administrator privileges 
    -  At the end of their stay, the intruders will just turn on auditing again using auditpol.exe
    - The attacker would establish a null session to the target machine and run the command:
        -  C:\auditpol \<ip address of target> 
            - This will reveal the current audit status of the system. 
    - He or she can choose to disable the auditing by: 
        - C :\auditpol \<ip address of target> /disable 
- CLearing logs
    - Clear_Event_Viewer_Logs.bat
        - utility that can be used to wipe out the logs of the target system.
    - clearlogs.exe 
        -  clear the security, system, and application logs using the following options 
            -  C:\clearlogs.exe -app(for clearing application logs) 
            - C:\clearlogs.exe -sec(for clearing application logs)
            - C:\clearlogs.exe -sys(for clearing application logs)
    - clear logs using meterpreter shell
        1. Launch meterpretershell prompt of the Metasploit Framework. 
        2. Type clearev command in meterpreter shell prompt and press Enter. The logs of the target system will start being wiped out.
- Manually Clearing Event Logs 
    - Win
        - Navigate to Start/ Control Panel/System and Security/Administrative Tools/double click Event Viewer
        - Delete the all the log entries logged while compromising of the system
    - Linux
        - Navigates to /var/log directory on the Linux system 
        - Open plain text file containing log messages with text editor 
            - /var/log/messages 
        - Delete all the log entries logged while compromising of the system
- Ways to Clear Online Tracks
    - Remove Most Recently Used (MRU), delete cookies, clear cache, turn off AutoComplete, and clear Toolbar data from the browsers
    - From the Privacy Settings in Windows 10
    - From the Registry in Windows 10
        - Open the Registry Editor and navigate to HKEY_LOCAL_MACHINE\SOFTWARE\ Microsoft\Windows\CurrentVersion\
        Explorer and then remove the key for “Recent Docs”
        -  Delete all the values except "(Default)"
- Covering BASH Shell Tracks
    - The BASH is an sh-compatible shell which stores command history in a file called bash_history 
    - You can view the saved command history using more ~/.bash_history command
    - commands
        - Disabling history 
            - export HISTSIZE=0 
        - Clearing the history 
            - history –c
            - history -w
                - This command only deletes the history of the current shell whereas the command history of other shells remain unaffected
        - Clearing the user's complete history 
            - cat /dev/null > ~.bash_history&& history –c && exit
        - Shredding the History 
            - shred ~/.bash_history 
            - shred ~/.bash_history&& cat /dev/null > .bash_history&& history -c && exit
                - This command firstly, shreds the history file, then deletes it and finally clears the evidence of using this command.
- Covering Tracks on Network
    - Using Reverse HTTP Shells
        - Attacker installs reverse HTTP shell on victim’s machine, which is programmed in such a way that it would ask for commands to an external master who controls the reverse HTTP shell
        - Victim here will act as a web client who is executing HTTP GET commands whereas the attacker behaves like a web server and responds to the requests
        - This type of traffic is considered as a normal traffic by an organization’s network perimeter security like DMZ, firewall, etc
    - Using Reverse ICMP Tunnels
        - Attacker uses ICMP tunneling technique to use ICMP echo and ICMP reply packets as a carrier of TCP payload, to access or control a system stealthily
    - Using DNS Tunneling
    - Using TCP Parameters































       






        


