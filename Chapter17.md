# mobile platform attack vectors

### Anatomy of mobile attacks

- device
  -  Browser-Based Attacks 
     -  phising
     -  framing
     -  Clickjacking: 
        -  Clickjacking, also known as a user interface redress attack, is a malicious technique used to trick web users to click something different from what they think they are clicking. Consequently, attackers obtain sensitive information or take control of the device.
     - man in the middle
     - buffer overflow
     - data caching
       - Data caches in mobile devices store information that is often required by mobile devices to interact with web applications, thereby saving scarce resources and resulting in better response time for the client application. Attackers attempt to exploit these data caches to gain sensitive information stored in them
    -  Phone/SMS-based Attacks 
       - Baseband Attacks:
           -    Attackers exploit vulnerabilities resident in a phone’s GSM/3GPP baseband processor, which sends and receives radio signals to cell tower
        - SMiShing 
   - Application-based Attacks 
     - Sensitive Data Storage
     - No Encryption/Weak Encryption:
     - Improper SSL Validation
     - Configuration Manipulation
     - Dynamic Runtime Injection
     - Escalated Privileges
   - System based
     - rooting
     - os data caching
     -  Carrier-loaded Software:
     -  User-initiated Code:

- Network
  - session hujacking, mitm, etc are the sam
  -  SSLStrip: 
     -  SSLStrip is a type of MITM attack in which attackers exploit vulnerabilities in the SSL/TLS implementation on websites
  - Fake SSL Certificates: 
    - Fake SSL certificates represent another kind of MITM attack, in which an attacker issues a fake SSL certificate to intercept traffic on a supposedly secure HTTPS connection.
- Data centers
  - Web server-based attacks 
    - Platform Vulnerabilities
    - Server Misconfiguration
    - Cross-site Scripting (XSS):
    - Cross-Site Request Forgery (CSRF)
    - Weak Input Validation
    - Brute-Force Attacks:
  - DataBase attacks
  
### other issues

-  App sandboxing 
   -  is a security mechanism that helps protect systems and users by limiting resources the app can access to its intended functionality on the mobile platform. Often, sandboxing is useful in executing untested code or untrusted programs from unverified third parties, suppliers, untrusted users, and untrusted websites
- Mobile Spam

# Hacking Android OS

- android features
  -  Shared Preferences—Store private primitive data in key-value pairs
  -  internal Storage—Private data on the device memory
  -  External Storage—Public data on the shared external storage 
  -  SQLite Databases—Store structured data in a private database 
  -  Network Connection—Store data on the web with your own network server

- Android OS Architecture 
  -  System Applications 
  -  Java API Framework
  -  Native C/C++ Libraries
  - Android Runtime 
  - Hardware Abstraction Layer
  - Linux Kernel

- Android Device Administration API 
  - the Device Administration API introduced in Android 2.2 provides device administration features at the system level
  - These APIs allow developers to create security-aware applications that are useful in enterprise settings, in which IT professionals require rich control over employee devices
  - the policies supported by the Android device administration API:
    - Password enabled policy etc

### android rooting
     
- Rooting enables all the user-installed applications to run privileged commands such as:
  - Modifying or deleting system files, module, ROMs (stock firmware), and kernels
  - Removing carrier-or manufacturer-installed applications (bloatware)
  - Low-level access to the hardware that are typically unavailable to the devices in their default configuration
  - Wi-Fi and Bluetooth tethering 
  - Install applications on SD card

# Hacking iOS

- layers of iOS: 
  - Cocoa Touch: 
    - This layer contains key frameworks that help in building iOS apps. These frameworks define the appearance of app, offers basic app infrastructure, and supports key technologies such as multitasking, touch-based input, push notifications, and many high-level system services.
  -  Media: 
     -  This layer contains the graphics, audio, and video technologies that enable multimedia experiences in apps.
  -  Core Services: 
     -  This layer contains fundamental system services for apps. Key among these services are Core Foundation and Foundation frameworks (defines the basic types that all apps use). Individual technologies that support features such as social media, iCloud, location, and networking belong to this layer.
  -  Core OS: 
     -  This layer contains low-level features on which most other technologies are built. Frameworks in this layer are useful when dealing explicitly with security or communicating with an external hardware accessory.

- Types of Jailbreaking 
  -  Userland Exploit
     -   Userland Exploit uses a loophole in the system application. It allows user-level access but does not allow iboot-level access. You cannot secure iOS devices against this exploit, as nothing can cause a recovery mode loop. Only firmware updates can patch these types of vulnerabilities.
   -  iBoot Exploit 
      -  This type of exploit can be semi-tethered if the device has a new bootrom. An iboot jailbreak allows user-level access and iboot-level access. This exploit takes advantage of a loophole in iBoot (iDevice’s third bootloader) to delink the code-signing appliance. Firmware updates can patch these types of exploits.
   -  Bootrom Exploit
      -   Bootrom Exploit uses a loophole in the SecureROM (iDevice’s first bootloader) to disable signature checks, which can be used to load patch NOR firmware. Firmware updates cannot patch these types of exploits. A bootrom jailbreak allows user-level access and iboot-level access. Only a hardware update of bootrom by Apple can patch this exploit.
- Jailbreaking Techniques 
  -  Untethered Jailbreaking
     -   An untethered jailbreak has the property that if the user turns the device off and back on, the device will start up completely, and the kernel will be patched without the help of a computer—in other words, it will be jailbroken after each reboot.
   - Semi-tethered Jailbreaking
     -  A semi-tethered jailbreak has the property that if the user turns the device off and back on, the device will start up completely, it will no longer have a patched kernel, but it will still be usable for normal functions. To use jailbroken addons, the user need to start the device with the help of the jailbreaking tool.
  - Tethered Jailbreaking
    -  With a tethered jailbreak, if the device starts up on its own, it will no longer have a patched kernel, and it may get stuck in a partially started state; in order for it to start completely and with a patched kernel, it essentially must be “re-jailbroken” with a computer (using the “boot tethered” feature of a jailbreaking tool) each time it is turned on.

# Mobile spyware
- Mobile spyware is a software tool that gives you full access to monitor a victim’s phone 
- It secretly records all activity on the phone such as Internet use, text messages, phone calls, etc.
- Then you can access the logged information via the software’s main website, or you can also get this tracking information through SMS or email

# Mobile Device Management

- Mobile Device Management (MDM) provides platforms for over-the-air or wired distribution of applications, data and configuration settings for all types of mobile devices, including mobile phones, smartphones, tablet computers, etc.
- MDM helps in implementing enterprise-wide policies to reduce support costs, business discontinuity, and security risks
- It helps system administrators to deploy and manage software applications across all enterprise mobile devices to secure, monitor, manage, and supports mobile devices

