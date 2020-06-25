# WebServer concepts

### components of a web server

- Document Root: 
    - Stores critical HTML files related to the web pages of a domain name
    - that will be served in response to the requests
- Server Root: 
    - Stores server's configuration, error, executable and log files
- Virtual Document Tree:
    - Provides storage on a different machine or disk after the original disk is filled up
- Virtual Hosting:
    - Technique of hosting multiple domains or websites on the same server
- Web Proxy: 
    - Proxy server that sits in between the web client and web server to prevent IP blocking and maintain anonymity


### open soure web architecture

 - Open-source web server architecture typically uses Linux, Apache, MySQL, and PHP (LAMP) as principal components. 
 - Following are the functions of principal components in open source web server architecture: 
    - Linux 
        - is the server’s OS that provides secure platform for the web server 
    - Apache 
        -is the web server component that handles each HTTP request and response 
    - MySQL 
        - is a relational database used to store the web server’s content and configuration information
    - PHP 
        - is the application layer technology used to generate dynamic web content
# web server attacks

- DoS/DDoS
- DNS server hijacking
    - Attacker compromises DNS server and changes the DNS settings so that all the requests coming towards the target web server are redirected to his/her own malicious server
- DNS amplification
    - dos attack
    - Attacker takes advantage of DNS recursive method of DNS redirection to perform DNS amplification attack
    - Recursive DNS Query is a method of requesting DNS mapping. The query goes through domain name servers recursively until it fails to find the specified domain name to IP address mapping.

- directory traversal
    - In directory traversal attacks, attackers use ../ (dot-dot-slash) sequence to access restricted directories outside of the web server root directory 
- Man-in-the-Middle (MITM)/sniffing, 
- phishing, 
- website defacement,
- web server misconfiguration, 
    -  Following are some of the web server misconfigurations: 
        - Verbose Debug/Error Messages
        - Anonymous or Default Users/Passwords
        -  Sample Configuration and Script Files
        - Remote Administration Functions 
        - Unnecessary Services Enabled 
        - Misconfigured/Default SSL Certificates
- HTTP response splitting,
    - HTTP response splitting attack involves adding header response data into the input field so that the server splits the response into two responses 
    - The attacker can control the first response to redirect the user to a malicious website whereas the other responses will be discarded by the web browser
    - This type of attack exploits vulnerabilities in input validation. 
    - examples
        - Cross-Site Scripting (XSS)
        - Cross-Site Request Forgery (CSRF)
        - SQL Injection 
- web cache poisoning
    - Web cache poisoning attacks the reliability of an intermediate web cache source
    - In this attack, the attackers swap cached content for a random URL with infected content
    - Users of the web cache source can unknowingly use the poisoned content instead of the true and secured content when requesting the required URL through the web cache
- SSH brute force, 
- web server password cracking

# web server attack methodology

### stages of web server’s attack methodology:
- Information Gathering 
    - WHOis
    - Information Gathering from Robots.txt File
        - The robots.txt file contains the list of the web server directories and files that the web site owner wants to hide from web crawlers
        - An attacker can simply request Robots.txt file from the URL and retrieve sensitive information such as root directory structure, content management system information, etc., about the target website
    - banner grabbing
    - tools
        - netcat
        - telnet
        - Netcraft
            - determines the OS of the queried host by looking in detail at the network characteristics of the HTTP response received from the website. Netcraft identifies vulnerabilities in the web server via indirect methods
        -  httprecon 
            - tool for advanced web server fingerprintinf
        - nmap PAGE 1349
- Web Server Footprinting
- Website Mirroring
    - Most of the web application servers contain default content and functionalities allowing attackers to leverage attacks
    - Use tools like Nikto2 (https://cirt.net) and exploit databases like SecurityFocus (http://www.securityfocus.com) to identify the default content
     - Directory listings sometimes possess the following vulnerabilities that allow the attackers to compromise web server 
        - Improper access controls 
        - Unintentional access to web root of servers
- Vulnerability Scanning
- Session Hijacking
- Web Server Passwords Hacking

# web server attack tools 

### metadploit

- The Metasploit Framework is a exploit development platform which supports fully automated exploitation of web servers, by abusing known vulnerabilities and leveraging weak passwords via Telnet, SSH, HTTP, and SNM
- Modules
    - Metasploit Exploit Module
        - it is the basic module in Metasploit used to encapsulate an exploit with the help of which users target many platforms with a single exploit
        - This module comes with simplified meta-information fields
        - Using a Mixins feature, users can also modify exploit behavior dynamically, brute force attacks, and attempt passive exploits
    - Payload Module
        - establishes a communication channel between the Metasploit framework and the victim host 
        - It combines the arbitrary code that is executed as a result of an exploit succeeding 
        - To generate payloads, first select a payload using the command as shown in the screenshot
    - Auxiliary modules 
        - can be used to perform arbitrary, one-off actions such as port scanning, denial of service, and even fuzzing
        - To run the auxiliary module, either use the run command, or use the exploit command
    - NOP modules
        - generate a no-operation instruction used for blocking out buffers - Use generate command to generate a NOP sled of an arbitrary size and display it in a given format 
        - OPTIONS: 
            - -b opt: The list of characters to avoid: '\x00\xff' 
            - -h: Help banner 
            - -s opt: The comma separated list of registers to save
            -  -t opt: The output type: ruby, perl, c, or raw

# Countermeasures

- Place Web Servers in Separate Secure Server 
    - An ideal web hosting network should be designed with at least three segments namely Internet segment, secure server security segment often called demilitarized zone (DMZ), and internal network
    - Place the web server in Server Security Segment (DMZ) of the network, isolated from public network as well as internal network 
    - Firewalls should be in place for internal network as well as Internet traffic going towards DMZ
- Patches and Updates
- Disable WebDAV 
    - if not used by the application or keep secure if it is required. 
- Eliminate unnecessary files within the .jar files
- Use Website Change Detection System to detect hacking attempts on the web server 
- Limit inbound traffic to port 80 for HTTP and port 443 for HTTPS (SSL)
- Encrypt or restrict intranet traffic
- Ensure that protected resources are mapped to HttpForbiddenHandler and unused HttpModules are removed
- Ensure that tracing is disabled --trace enable="false" -- and debug compiles are turned off
- Configure IIS to reject URLs with "../" and install new patches and updates
- Remove unnecessary ISAPI filters from the web server
-  Disallow carriage return (%0d or \r) and line feed (%0a or \n) characters 



