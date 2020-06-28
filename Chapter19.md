### Cloud infrasctuture factors

- Cloud Consumer: 
  - A cloud consumer is a person or organization that maintains a business relationship with cloud service providers and uses cloud computing services. The cloud consumer browses the CSP’s service catalog requests for the desired services, sets up service contracts with the CSP (either directly or via cloud broker) and uses the service. 
- Cloud Provider: 
  - A cloud provider is a person or organization who acquires and manages the computing infrastructure intended for providing services (directly or via a cloud broker) to interested parties via network access. 
- Cloud Broker:
  -  Integration of cloud services is becoming too complicated for cloud consumers to manage. Thus, a cloud consumer may request cloud services from a cloud broker, rather than directly contacting a CSP. The cloud broker is an entity that manages cloud services regarding use, performance, and delivery, and maintains the relationship between CSPs and cloud consumers.
- Cloud Carrier: 
  - A cloud carrier acts as an intermediary that provides connectivity and transport services between CSPs and cloud consumers. The cloud carrier provides access to consumers via a network, telecommunication, and other access devices.

### types of virtualizations

- Storage Virtualization
  - It combines storage devices from multiple networks into a single storage device and helps in:
    - Expanding the storage capacity
    - Making changes to store configuration easy

- Network Virtualization
  - It combines all network resources, both hardware, and software into a single virtual network and is used to:
    - Optimize reliability and security
    - Improves network resource usage
- Server Virtualization
  - It splits a physical server into multiple smaller virtual servers. Storage utilization is used to:
    - Increase the space utilization
    - Reduces the hardware maintenance cost

### cloud computing threats

- Isolation Failure: 
  - Multi-tenancy and shared resources are the characteristics of cloud computing. Strong isolation or compartmentalization of storage, memory, routing, and reputation among different tenants is lacking. Because of isolation failure, attackers try to control operations of other cloud customers to gain illegal access to the data.
- Privilege Escalation:
  -  A mistake in the access allocation system causes a customer, third party, or employee to get more access rights than needed.
- Illegal Access to the cloud: 
  - Attackers can exploit weak authentication and authorization to get illegal access, thereby compromising confidential and critical data stored in the cloud.
- Supply Chain Failure: 
  - A disruption in the chain may lead to loss of data privacy and integrity, unavailability of services, violation of SLA, economic and reputational losses resulting in failure to meet customer demand, and cascading failure.
- Abuse and Nefarious Use of Cloud services: 
  - Presence of weak registration systems in the cloud-computing environment gives rise to this threat. Attackers create anonymous access to cloud services and perpetrate various attacks such as password and critical cracking, building rainbow tables, CAPTCHA-solving farms, launching dynamic attack points, hosting exploits on cloud platforms, hosting malicious data, Botnet command or control, DDoS, etc. 
- Insecure Interface and APIs:
  -  Attackers exploit user defined policies, reusable passwords/tokens, insufficient input-data validation.
- Data Breach/Loss: 
  - Attackers gain illegal access to the data and misuse or modify the data.
- Insufficient Due Diligence:
  -  Ignorance of CSP’s cloud environment poses risks in operational responsibilities such as security, encryption, incident response, and more issues such as contractual issues, design and architectural issues, etc.
- privilege escalation: A mistake in the access allocation system such as coding errors, design flaws, and others can result in a customer, third party, or employee obtaining more access rights than required. This threat arises because of AAA (authentication, authorization, and accountability) vulnerabilities, user-provisioning and de-provisioning vulnerabilities, hypervisor vulnerabilities, unclear roles and responsibilities, misconfiguration, and others.
- Illegal Access to the Cloud:
  -  Weak authentication and authorization controls could lead to illegal access thereby compromising confidential and critical data stored in the cloud.
- Isolation Failure: 
  - Due to isolation failure, cloud customers can gain illegal access to the data.
- Modifying Network Traffic:
  -  Due to flaws while provisioning or de-provisioning network or vulnerabilities in communication encryption.

### Attacks

- Cybersquatting: 
  - Involves conducting phishing scams by registering a domain name that is similar to a cloud service provider.
- Domain hijacking: 
  - Involves stealing a cloud service provider’s domain name.
- Domain snipping:
  -  Involves registering an elapsed domain name.
- Service Hijacking Using Social Engineering Attacks: 
  - In account or service hijacking, an attacker steals a CSP’s or client’s credentials by methods such as phishing, pharming, social engineering, and exploitation of software vulnerabilities. Using the stolen credentials, the attacker gains access to the cloud computing services and compromises data confidentiality, integrity, and availability.
- Wrapping Attack: 
  - It is performed during the translation of SOAP messages in the TLS layer, where attackers duplicate the body of the message and send it to the server as a legitimate user.
- DNS Attack: 
  - The attacker performs DNS attacks to obtain authentication credentials from Internet users.
  - types
    - Domain snipping, 
    - domain hijacking,
    - cybersquatting 
- Side Channel Attack:
  -  The attacker compromises the cloud by placing a malicious virtual machine near a target cloud server and then launches a side channel attack.
  - Inside channel attack, the attacker runs a virtual machine on the same physical host of the victim’s virtual machine and takes advantage of shared physical resources (processor cache) to steal data (cryptographic key) from the victim. Side-channel attacks can be implemented by any co-resident user and are mainly due to the vulnerabilities in shared technology resources.
  - types
    - Timing attack, 
    - data remanence,
    - acoustic cryptanalysis 
- Session Hijacking Using Session Riding: 
  - Attackers exploit websites by engaging in cross-site request forgeries to transmit unauthorized commands. In session riding, attackers “ride” an active computer session by sending an email or tricking users to visit a malicious web page, during login, to an actual target site. When users click the malicious link, the website executes the request as if the user had already authenticated it. Commands used include modifying or deleting user data, performing online transactions, resetting passwords, and others.

### Cloud Security Control Layers
- Information Layer
  - Develop and document an information security management program (ISMP), which includes administrative, technical, and physical safeguards to protect information against unauthorized access, modification, or deletion. Some of the information layer security controls include DLP, CMF, database activity monitoring, encryption, etc.
- Trusted Computing
  - Trust computing defines secured computational environment that implements internal control, auditability, and maintenance to ensure availability and integrity of cloud operations. Hardware and software RoT & API's are few security controls for trusted computing.
- Physical Layer
  - This layer includes security measures for cloud infrastructure, data centers, and physical resources. Security entities that come under this perimeter are physical plant security, fences, walls, barriers, guards, gates, electronic surveillance, CCTV, physical authentication mechanisms, security patrols, and so on.
- Application Layer
  - To harden the application layer, establish the policies that match with industry adoption security standards, for example, OWASP for a web application. It should meet and comply with appropriate regulatory and business requirements. Some of the application layer controls include SDLC, binary analysis, scanners, web app firewalls, transactional sec, etc.
  
- Management Layer
  - This layer covers the cloud security administrative tasks, which can facilitate continued, uninterrupted, and effective services of the cloud. Cloud consumers should look for the above-mentioned policies to avail better services. Some of the management layer security controls include GRC, IAM, VA/VM, patch management, configuration management, monitoring, etc.
- Network Layer
  - It deals with various measures and policies adopted by a network administrator to monitor and prevent illegal access, misuse, modification, or denial of network-accessible resources. Some of the additional network layer security controls include NIDS/NIPS, firewalls, DPI, anti-DDoS, QoS, DNSSEC, OAuth, etc.
- Computation and Storage
  - In cloud due to the lack of physical control of the data and the machine, the service provider may be unable to manage the data and computation and lose the trust of the cloud consumers. Cloud provider must establish policies and procedures for data storage and retention. Cloud provider should implement appropriate backup mechanisms to ensure availability and continuity of services that meet with statutory, regulatory, contractual, or business requirements and compliance. Host-based firewalls, HIDS/HIPS, integrity and file/log management, encryption, masking are some security controls in computation and storage.

### security controls
- Deterrent Controls: 
  - These controls reduce attacks on the cloud system. Example: Warning sign on the fence or property to inform adverse consequences for potential attackers if they proceed to attack
- Preventive Controls: 
  - These controls strengthen the system against incidents, probably by minimizing or eliminating vulnerabilities. Example: Strong authentication mechanism to prevent unauthorized use of cloud systems.
- Detective Controls: 
  - These controls detect and react appropriately to the incidents that happen. Example: Employing IDSs, IPSs, etc. helps to detect attacks on cloud systems.
- Corrective controls: 
  - These controls minimize the consequences of an incident, probably by limiting the damage. Example: Restoring system backups.
