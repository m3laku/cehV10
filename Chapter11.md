#  Session Hijacking Concepts#
- Session hijacking refers to an attack where an attacker takes over a valid TCP communication session between two computers
- Since most authentication only occurs at the start of a TCP session, this allows the attacker to gain access to a machine
- Attackers can sniff all the traffic from the established TCP sessions and perform identity theft, information theft, fraud, etc.
- The attacker steals a valid session ID and uses it to authenticate himself with the server
- Why Session Hijacking is Successful? 
  - Weak session-ID generation algorithm or small session IDs
  - Indefinite session-timeout
  - Insecure handling of session IDs
  - Computers using TCP/IP are vulnerable:
  - No account lockout for invalid session IDs
-  Session Hijacking Process
    1. sniff
    2. monitor
    3. Session Desynchronization
         - To desynchronize the connection between the target and the host, the attacker must change the sequence number or acknowledgment number (SEQ/ACK) of the server. To do this, the attacker sends null data to the server so that the server’s SEQ/ACK numbers will advance, while the target machine will not register the increment.   
    4. Session ID Prediction
    5. command injection
- types
    - active
      - In an active attack, an attacker finds an active session and takes over
    - passive
      - In a passive attack, an attacker hijacks a session but sits back and watches and records all the traffic in that session
- Session Hijacking in OSI Model 
  - Network level hijacking
    -  can be defined as the interception of the packets during the transmission between the client and the server in a TCP and UDP session
   - application level hijacking 
     - is about gaining control over the HTTP’s user session by obtaining the session IDs

# Application Level Session Hijacking
- In a session hijacking attack, a session token is stolen or a valid session token is predicted to gain unauthorized access to the web server
-  An attacker implements various techniques to get a valid session ID 
   -  stealing,
   -  guessing, 
   -   brute forcing 

### A session token can be compromised in various ways: 
- Session sniffing
  - Attacker uses a sniffer to capture a valid session token or session ID
  - Attacker then uses the valid token session to gain unauthorized access to the web server
- Predict a session token
  - Attackers can predict session IDs generated by weak algorithms and impersonate a web site user
- Man-in-the-middle attack
- man-in-the-browser attack
  - uses a Trojan Horse to intercept the calls between the browser and its security mechanisms or libraries

- Cross-site scripting (XSS) attack
  - XSS enables attackers to inject malicious client side scripts into the web pages viewed by other users

- Cross-site request forgery attack
  - Cross-Site Request Forgery (CSRF) attack exploits a victim’s active session with a trusted site in order to perform malicious activities
  - attacker forces the victim to submit the attacker’s form data to the victim’s Web server. The attacker creates the host form, containing malicious information, and sends it to the authorized user. The user fills in the form and sends it to the server. Because the data is coming from a trusted user, the Web server accepts the data. Unlike XSS attack, which exploits the trust a user has for a particular website, CSRF exploits the trust that a website has in a user’s browser.

- Session replay attack
  - In a session replay attack, the attacker listens to the conversation between the user and the server and captures the authentication token of the user
  - Once the authentication token is captured, the attacker replays the request to the server with the captured authentication token and gains unauthorized access to the server


- Session fixation attack 
  - Attacker exploits the vulnerability of a server which allows a user to use fixed SID 
  - Attacker provides a valid SID to a victim and lures him to authenticate himself using that SID
  - The attack tries to lure a user to authenticate himself with a known session ID and then hijacks the user-validated session by the knowledge of the used session ID
  - Several techniques to execute session fixation attack are: 
    - Session token in the URL argument 
    - Session token in a hidden form field 
    - Session ID in a cookie

- CRIME attack 
  - CRIME (Compression Ratio Info-Leak Made Easy) is a client-side attack which exploits the vulnerabilities present in data compression feature of protocols such as SSL/TLS, SPDY, and HTTPS
  - Attackers hijack the session by decrypting secret session cookies
  - authhentication information obtained from the session cookies is used to establish a new session with the web application
- Forbidden attack
  - Forbidden attack is a type of man-in-the-middle attack used to hijack HTTPS sessions 
  - It exploits reusing of cryptographic nonce during the TLS handshake
  - After hijacking the HTTPS session, the attackers inject malicious code and forged content that prompts the victim to disclose sensitive information like bank account numbers, passwords, social security numbers, etc
- using proxy servers
  - Attacker lures the victim to click on a bogus link which looks legitimate but redirects the user to the attacker server
  - Attacker forwards the request to the legitimate server on the behalf of the victim and serves as a proxy for the entire transaction
  - Attacker then captures the sessions information during the interaction of the legitimate server and the user

# Network level hijacking

- Attackers especially focus on network-level session hijacking, as it does not require host access, as would host-level session hijacking, and they need not tailor their attacks on a per-application basis, as they would at the application level.
- 3way handshake
-  For communication, the following information is required: 
      - IP address 
      - Port numbers
      - Sequence numbers
 ### types of network layer hijacking

- Blind Hijacking 
  - The attacker can inject the malicious data or commands into the intercepted communications in the TCP session even if the source-routing is disabled
  - The attacker can send the data or commands but has no access to see the response
- UDP Hijacking 
  - A network-level session hijacking where the attacker sends forged server reply to a victim’s UDP request before the intended server replies to it
The attacker uses man-in-the-middle attack to intercept server’s response to the client and sends its own forged reply

- TCP/IP Hijacking
  - TCP/IP hijacking uses spoofed packets to take over a connection between a victim and a target machine
  -  The victim's connection hangs, and the attacker is then able to communicate with the host’s machine as if the attacker is the victim 
  -  To launch a TCP/IP hijacking attack, the attacker must be on the same network as the victim 
  -  The target and the victim machines can be located anywhere
- RST Hijacking
  - RST hijacking involves injecting an authentic-looking reset (RST) packet using spoofed source address and predicting the acknowledgment number
  - The hacker can reset the victim’s connection if it uses an accurate acknowledgment number 
  - The victim believes that the source actually sent the reset packet and resets the connection
  - RST Hijacking can be carried out using a packet crafting tool such as Colasoft’s Packet Builder and TCP/IP analysis tool such as tcpdump
- Man-in-the-Middle: Packet Sniffer 
  - forged ICMP
  - forged ARP
- IP Spoofing: Source Routed Packets
  - Packet source routing technique is used for gaining unauthorized access to a computer with the help of a trusted host’s IP address

# countermeasures


- Approaches to Prevent Session Hijacking 
  -  HTTP Strict Transport Security (HSTS)
     -   HTTP Strict Transport Security (HSTS) is a web security policy that protects HTTPS websites against man-in-the-middle attacks. HSTS policy helps web servers to enforce web browsers to interact with it using secure HTTPS protocol. With HSTS policy, all the insecure HTTP connections are automatically converted into HTTPS connections. This policy ensures that all the communication between the web server and web browser is encrypted and all responses that are delivered and received are originated from an authenticated server.
  - Token Binding
    - When a user logs on to a web application, it generates a cookie with a session identifier, called token
    - Token binding protects client server communication against session hijacking attacks
  - HTTP Public key Pinning (HPKP) 
    - is Trust on First Use (TOFU) technique used in an HTTP header that allows a web client to associate a specific public key certificate with a particular server to minimize the risk of man-in-the-middle attacks with fraudulent certificates. In TLS sessions, to verify the authenticity of a server’s public key, the public key is enclosed in a X.509 digital certificate, which is signed by a Certification Authority (CA). Attackers by compromising any CA can perform man-in-the-middle attacks on various TLS sessions. HPKP protects TLS sessions from such type of attacks by delivering to the client, the list of public keys owned by a web server

### IPSec

- Components of IPsec 
  - IPsec driver: 
    - A software, that performs protocol-level functions required to encrypt and decrypt the packets.
  -  Internet Key Exchange (IKE): 
     -  IPsec protocol that produces security keys for IPsec and other protocols.
  - Internet Security Association Key Management Protocol; 
    - Software that allows two computers to communicate by encrypting the data exchanged between them.
  -  Oakley: 
     -  A protocol, which uses the Diffie-Hellman algorithm to create master key, and a key that is specific to each session in IPsec data transfer.
  -   IPsec Policy Agent: 
      -   A service of the Windows 2000 collects IPsec policy settings from the active directory and sets the system configuration system at startup.

- Modes
  - Transport Mode
    -  In transport mode (also ESP [Encapsulating Security Payload]), IPsec encrypts only the payload of the IP packet, leaving the header untouched. It authenticates two connected computers and provides the option of encrypting data transfer. It is compatible with NAT; therefore, can be used to provide VPN services for network utilizing NAT.
   -  Tunnel Mode
      -  In tunnel mode (also AH [Authentication Header]), the IPsec encrypts both the payload and header. Hence, there is more security in tunnel mode. After receiving, the IPsec-compliant device decrypts the data. Tunnel model is used to create VPNs over the Internet for network-to-network communication, host-to-network communication and host-to-host communication. It is compatible with NAT and supports NAT traversal.
-  Protocol structure of the IPsec architecture: 
   -  Authentication Header (AH): 
      -  It offers integrity and data origin authentication, with optional anti-replay features.
   -  Encapsulating Security Payload (ESP): 
      -  It offers all the services offered by Authentication Header (AH) and confidentiality.
   -  IPsec Domain of Interpretation (DOI): 
      -  It defines the payload formats, types of exchange, and naming conventions for security information such as cryptographic algorithm or security policies. IPsec DOI instantiates ISAKMP for use with IP when IP uses ISAKMP to negotiate security associations.
   - ISAKMP (Internet Security Association and Key Management Protocol): 
     - It is a key protocol in the IPsec architecture. It establishes the required security for various communications on the Internet such as government, private, and commercial, by combining the security concepts of authentication, key management, and security associations.
   -  Policy: 
      -  IPsec policies are useful in providing network security. They define when and how to secure data, and security methods to use at different levels in the network. One can configure IPsec policies to meet security requirements of a system, domain, site, organizational unit, and so on.
- security services for authentication and confidentiality
  -  Authentication Header (AH): 
     -  Provides data authentication of the sender 
  - Encapsulation Security Payload (ESP):
    -  Provides both data authentication and encryption (confidentiality) of the sender





  




  


