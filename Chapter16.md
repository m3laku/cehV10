### Notes

- In LAN-to-LAN Wireless Network, APs provide wireless connectivity to local computers, and computers on different networks can also be interconnected. All hardware APs have the capability to interconnect with other hardware APs. However, interconnecting LANs over wireless connections is a complex task.
- Bandwidth:
  -  It describes the amount of information that may be broadcasted over a connection. Usually, bandwidth refers to the data transfer rate. The unit of measuring the bandwidth is bits (amount of data) per second (bps)
- Hotspot:
  -  Places where wireless networks are available for public use. Hotspots refer to areas with Wi-Fi availability, where users can enable Wi-Fi on their devices and connect to the Internet through a hotspot.
- Access point (AP): 
  - Access point (AP) is used to connect wireless devices to a wireless/wired network. It allows wireless communication devices to connect to a wireless network through wireless standards such as Bluetooth and Wi-Fi. It serves as a switch or a hub between the wired LAN and wireless network.
- Association: 
  - The process of connecting a wireless device to an AP
Answer is access point.
- In a shared key authentication process, each wireless station receives a shared secret key over a secure channel that is distinct from the 802.11 wireless network communication channels. The following steps illustrate the establishment of connection in the shared key authentication process:
    - The station sends an authentication frame to the AP.
    - The AP sends a challenge text to the station.
    - The station encrypts the challenge text by making use of its configured 64- or 128-bit key, and it sends the encrypted text to the AP.
    - The AP uses its configured WEP key to decrypt the encrypted text. The AP compares the decrypted text with the original challenge text. If the decrypted text matches the original challenge text, the AP authenticates the station.
    - The station connects to the network.

- SSID 
  -  a human-readable text string with a maximum length of 32 bytes. The SSID is a token to identify an 802.11 (Wi-Fi) network; by default, it is a part of the frame header sent over a wireless local area network (WLAN). It acts as a single shared identifier between the access points and clients. If the SSID of the network is changed, reconfiguration of the SSID on every host is required, as every user of the network configures the SSID into their system. 
- WiMax
  -  This standard is a specification for fixed broadband wireless metropolitan access networks (MANs) that use a point-to-multipoint architecture. It has a range of 1609.34 – 9656.06 kilometers (1–6 miles).

- Radio frequencies
  - Orthogonal Frequency-division Multiplexing (OFDM):
    -  OFDM is a method of digital modulation of data in which a signal, at a chosen frequency, is split into multiple carrier frequencies that are orthogonal (occurring at right angles) to each other. OFDM maps information on the changes in the carrier phase, frequency, or amplitude, or a combination of these, and shares bandwidth with other independent channels. It produces a transmission scheme that supports higher bit rates than a parallel channel operation. It is also a method of encoding digital data on multiple carrier frequencies.

  - Multiple input, multiple output-orthogonal frequency-division 
       - multiplexing (MIMO-OFDM): MIMO-OFDM influences the spectral efficiency of 4G and 5G wireless communication services. Adopting the MIMO-OFDM technique reduces the interference and increases how robust the channel is.

  - Direct-sequence Spread Spectrum (DSSS): 
      - DSSS is a spread spectrum technique that multiplies the original data signal with a pseudo random noise spreading code. Also referred to as a data transmission scheme or modulation scheme, the technique  protects signals against interference or jamming.

  - Frequency-hopping Spread Spectrum (FHSS): 
      - Frequency-hopping Spread Spectrum (FHSS) is the method of transmitting radio signals by rapidly switching a carrier among many frequency channels. Direct-sequence Spread Spectrum (DSSS) refers to the original data signal and is multiplied with a pseudo random noise spreading code. Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM) is an air interface for 4G and 5G broadband wireless communications and Orthogonal Frequency-division Multiplexing (OFDM) is the method of encoding digital data on multiple carrier frequencies.

- antennas
  -  parabolic grid antenna 
       - uses the same principle as that of a satellite dish, but it does not have a solid backing. It consists of a semidish that is in the form of a grid made of aluminum wire. These parabolic grid antennas can achieve very long-distance Wi-Fi transmissions by using a highly focused radio beam. This type of antenna is useful for transmitting weak radio signals over very long distances – on the order of 10 miles. This enables attackers to get better signal quality, resulting in more data on which to eavesdrop, more bandwidth to abuse, and higher power output that is essential in layer 1 denial of service (DoS) and man-in-the-middle (MITM) attacks. The design of this antenna saves weight and space, and it can pick up Wi-Fi signals that are either horizontally or vertically polarized.
- encryption/authentication
  - RADIUS: 
    - It is a centralized authentication and authorization management system.
  - PEAP: 
    - It is a protocol that encapsulates the EAP within an encrypted and authenticated Transport Layer Security (TLS) tunnel.
  - LEAP: 
    - It is a proprietary version of EAP developed by Cisco.
  - CCMP: 
    - It is an encryption protocol used in WPA2 for stronger encryption and authentication.

- wireless standards
  - 802.11n:
    -  The IEEE 802.11n is a revision that enhances the earlier 802.11g standards with multiple-input multiple-output (MIMO) antennas. It works in both the 2.4 GHz and 5 GHz bands. This is an IEEE industry standard for Wi-Fi wireless local network transportations. Digital Audio Broadcasting (DAB) and Wireless LAN use OFDM.
  - 802.11i: 
     - The IEEE 802.11i standard improves WLAN security by implementing new encryption protocols such as TKIP and AES. It is a standard for wireless local area networks (WLANs) that provides improved encryption for networks that use the popular 802.11a, 802.11b (which includes Wi-Fi) and 802.11g standards.
   - 802.11d: 
     - The 802.11d is an enhanced version of 802.11a and 802.11b. The standard supports regulatory domains. The particulars of this standard can be set at the media access control (MAC) layer.
   - 802.11e: 
     - It is used for real-time applications such as voice, VoIP, and video. To ensure that these time-sensitive applications have the network resources they need, 802.11e defines mechanisms to ensure Quality of Service (QoS) to Layer 2 of the reference model, the medium-access layer, or MAC.
  
### Wireless hacking methodology

- To break WEP encryption the attacker follows these steps:
    - Start the wireless interface in monitor mode on the specific AP channel
      - In this step, the attacker sets the wireless interface to monitor mode. The interface can listen to every packet in the air. The attacker can select some packets for injection by listening to every packet available in the air.
    - Test the injection capability of the wireless device to the AP
      - The attacker tests whether the wireless interface is within the range of the specified AP and whether it is capable of injecting packets to it.
  - Use a tool such as aireplay-ng to do a fake authentication with the AP
    - The attacker ensures that the source MAC address is already associated, so that the AP accepts the injected packets. The injection will fail due to the lack of association with the AP.
  - Start the Wi-Fi sniffing tool
    - The attacker captures the IVs generated by using tools such as Cain & Abel and airodump-ng with a BSSID filter to collect unique IVs.
  - Start a Wi-Fi packet encryption tool such as aireplay-ng in ARP request replay mode to inject packets
    - To gain a large number of IVs in a short period, the attacker turns the aireplay-ng into ARP request replay mode, which listens for ARP requests and then re-injects them back into the network. The AP usually rebroadcasts packets generating a new IV. So in order to gain a large number of IVs, the attacker selects the ARP request mode.
  - Run a cracking tool such as Cain & Abel or aircrack-ng
    - Using cracking tools such as Cain & Abel or aircrack-ng the attacker can extract WEP encryption keys from the IVs.

### Attacks
- Beacon Flood
  - Generating thousands of counterfeit 802.11 beacons to make it hard for clients to find a legitimate AP.
  - tool: FakeAP
- Denial-of-Service
  - Exploiting the CSMA/CA Clear Channel Assessment (CCA) mechanism to make a channel appear busy.
  - method
    - An adapter that supports CW Tx mode, with a low-level utility to invoke continuous transmissions
- Routing Attacks
  - Distributing routing information within the network.
  - tools
    - RIP protocol
- Authenticate Flood
  - Sending forged authenticates or associates from random MACs to fill a target AP's association table.
  - tools
    - AirJack, File2air, Macfld, void11
- Evil twin AP: 
  - It is a rough access point masquerading as a genuine Wi-Fi access point. Once a user connects to it, the attacker can intercept confidential information.
- KRACK attack: 
  - KRACK attack stands for Key Reinstallation Attack. This attack exploits the flaws present in the implementation of a 4-way handshake process in WPA2 authentication protocol that is used toestablish a connection between a device and the Access Point (AP).
- War Driving: 
  - It is an act of searching and exploiting Wi-Fi wireless networks while driving around a city or elsewhere.
- WEP Cracking:
  -  It is a process of capturing data to recover a WEP key using WEP cracking tools such as Aircrack-ng.
-  Masquerading: 
   -  Pretending to be an authorized user to gain access t o a system.
- MITM attack: 
  - Running traditional MITM attack tools on an evil twin AP to intercept TCP sessions or SSL/SSH tunnels.
- Honeypot AP: 
  - Setting an AP's SSID to be the same as that of a legitimate AP.

### tools

- AIrDUmp !!!

### Bluetooth protocols
- Link management protocol (LMP):
  -  Is used for control of the radio link between two devices, handling matters such as link establishment, querying device abilities and power control. It is implemented on the controller.
- OBEX:
  -  Object Exchange protocol is used for communicating binary objects between devices. BlueJacking is sending anonymous messages to other Bluetooth-equipped devices via the OBEX protocol.
- Logical link control and adaptation protocol (L2CAP): 
  - L2CAP passes packets to either the Host Controller Interface (HCI) or on a hostless system, directly to the Link Manager/ACL link.
- Service discovery protocol (SDP): 
  - Is used to allow devices to discover what services each other support, and what parameters to use to connect to them.

### countermeasure tools
- CommView for WiFi: 
  - CommView for Wi-Fi is a wireless network monitor and analyzer for 802.11 a/b/g/n networks. It captures packets to display important information such as the list of APs and stations, per-node and per-channel statistics, signal strength, a list of packets and network connections, protocol distribution charts, etc. By providing this information, CommView for Wi-Fi can view and examine packets, pinpoint network problems, and troubleshoot software and hardware.
- WiFiFoFum: 
  - WiFiFoFum is a wardriving app to locate, display and map found WiFi networks. WiFiFoFum scans for 802.11 Wi-Fi networks and displays information about each including: SSID, MAC, RSSI, channel, and security. WiFiFoFum also allows you to connect to networks you find and log the location using the GPS. KML logs can be emailed.
- BlueScan: 
  - BlueScan is a bash script that implements a scanner to detect Bluetooth devices that are within the range of our system. BlueScan works in a non-intrusive way, that is, without establishing a connection with the devices found and without being detected. Superuser privileges are not necessary to execute it.
- WiFish Finder: 
  - WiFish Finder is a tool for assessing whether WiFi devices active in the air are vulnerable to ‘Wi-Fishing’ attacks. Assessment is performed through a combination of passive traffic sniffing and active probing techniques. Most WiFi clients keep a memory of networks (SSIDs) they have connected to in the past. Wi-Fish Finder first builds a list of probed networks and then using a set of clever techniques also determines security setting of each probed network. A client is a fishing target if it is actively seeking to connect to an OPEN or a WEP network.

- Wireless Intrusion Detection System (WIDS) 
  - analyzes and monitors the RF spectrum. Alarm generation helps in detecting unauthorized wireless devices that violate the security policies of the network.

### countermeasure notes
- Connection Security: 
  - Per frame/packet authentication provides protection against MITM attacks. It does not allow the attacker to sniff data when two genuine users are communicating with each other, thereby securing the connection.
- Defend Against WPA/WPA2 Cracking
  - Passphrases 
  - The only way to crack WPA is to sniff the password PMK associated with the “handshake” authentication process, and if this password is extremely complicated, it will be almost impossible to crack. 
  - Select a random passphrase that is not made up of dictionary words 
  - Select a complex passphrase of a minimum of 20 characters in length and change it at regular intervals
- RF Scanning:
  -  Re-purposed access points that do only packet capturing and analysis (RF sensors) are plugged in all over the wired network to detect and warn the WLAN administrator about any wireless devices operating in the area.
- Wired Side Inputs: 
  - Network management software uses this technique to detect rogue APs. This software detects devices connected in the LAN, including Telnet, SNMP, CDP (Cisco discovery protocol) using multiple protocols.
- AP Scanning: 
  - Access points that have the functionality of detecting neighboring APs operating in the nearby area will expose the data through its MIBS and web interface.
- Virtual-Private-Network:
  -  A Virtual Private Network (VPN) is a network that provides secure access to the private network through the internet. VPNs are used for connecting wide area networks (WAN). It allows computers on one network to connect to computers on another network. 



