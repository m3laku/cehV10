# Footprinting concepts

## passive
  -  Performing passive footprinting is technically difficult, as active traffic is not sent to the target organization from a host or from anonymous hosts or services over the Internet
  ## active
  - the target may recognize the ongoing information gathering process, as we overtly interact with the target network
  -  Querying published name servers of the target 
  -   Extracting metadata of published documents and files 
  -   Gathering website information using web spidering and mirroring tools
  -   Gathering information through email tracking 
  -   Performing Whois lookup 
  -   Extracting DNS information
  -   Performing traceroute analysis
  -   Performing social engineering

  ## information obtained in footprinting:
  - organization information
  - network information
  - system information

## objectives of footprinting
- know security posture
- reduce focus area
- identify vulnerabilities
- draw network map

## footprinting threats
- Social Engineering
- System and Network Attacks
- Information Leakage
- Privacy Loss
- Corporate Espionage

# Footprinting Metodology

## footprinting through search engines -- google hacking
-  returns Search Engine Results Pages (SERP)
-  advaced google search operators:
   -  site: This operator restricts search results to the specified site or domain
   -  allinurl: This operator restricts results to only those pages containing all the query terms specified in the URL.

   -  inurl: This operator restricts the results to only those pages containing the word specified in the URL
    - allintitle: This operator restricts results to only those pages containing all the query terms specified in the title
   - intitle: This operator restricts results to only those pages containing the specified term in the title.
   - inanchor: This operator restricts results to only those pages containing the query terms specified in the anchor text on links to the page
   - related
   - info
   - location
   - fileType
 -  Google Advanced Search and Advanced Image Search, one can search web more precisely and accurately. You can use these search features to achieve same precision as of using the advanced operators but without typing or remembering the operators
 
 “site” Google search operator restricts search results to the specified site or domain. It allows you to see the URLs they have indexed of your website. Adding [-] to most operators tells Google to search for anything but that particular text.

Here, the query will search for “accounting” in target.com domain but not on the Marketing.target.com domain because [-] is added before the Marketing.target.com domain in the query.

- Google Hacking Database:
  - authoritative source for querying the ever-widening reach of the Google search engine. In the GHDB, you will find search terms for files containing usernames, vulnerable servers, and even files containing passwords

- voip and VPN footprinting -- PAGE 178!!!!

## Footprinting through web services
- Finding Company’s Top-level Domains (TLDs) and Sub-domains
    - netCraft
    - sublist3r
      - syntax: 
sublist3r [-d DOMAIN] [-b BRUTEFORCE] [-p PORTS] [-v VERBOSE][-t THREADS] [-e ENGINES] [-o OUTPUT]

-   People Search on Social Networking Sites
    -   tools: pipl.com 
        -    pipl is an online people search tool to find other users through their name, email, username or phone number. It has an Identity Resolution engine that focuses on finding the right person and provides accurate results for people search.
- Gathering Information from LinkedIn
  - tools: inSpy  - linkedIn enumeration tool

- Gathering Information from Financial Services
  - tool: google finance

- determining the operation system
  - tools: netCraft, Shodan

## Website Footprinting


- Website footprinting can be performed by examining:
  - HTML source code 
  -  cookies.
- Website Footprinting using Web Spiders:
  - Web spiders perform automated searches on the target website and collect specified information such as employee names, email addresses, etc.
    - Web spidering fails if the target website has the robots.txt file in its root directory, with a listing of directories to prevent crawling.
- Mirroring Entire Website
- Extracting Website Information from https://archive.org
- Extracting Metadata of Public Documents
  - tools: metagoofil

- Monitoring Web Pages for Updates and Changes
  - Web updates monitoring tools are capable of detecting any changes or updates in a particular website and can give notifications or send alerts to the interested users through email or SMS. 
  - tools: 
    - WebSite-Watcher

## Tracking Email Communication

- information gathered:
  - Recipient's system IP address
  -   Geolocation
  - Email received and Read
  - Read duration
  - Proxy detection
  - Links
  - Operating system and Browser information
  - Forward Email:
  - device type
- email header: PAGE 212
- email tracking tools:
  - eMailTrackerPro

## Competitive Intelligence

- points to note:
  - When did it begin
  - How did it develop - plans
    - alexa.com - analitycs tool
  - Who leads it? 
  - Where is it located?
  - What Expert Opinions Say About the Company
  -  Monitoring Website Traffic of Target Company
  - Tracking Online Reputation of the Target:
    - onlineReputationManagement - ORM
    - tool: trackur

- sources of competitive intelligence:
  - direct approach
  - indirect approach
  - sites:
    - EDGAR database
    - Hoovers: business research site
    - LexisNexis: legal and public=records related information
    - Business Wire: focuses on press release distribution and regulatory disclosure
    - FACTIVA: Factiva is a global news database and licensed content

## Whois footprinting

- Whois is a query and response protocol used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system. This protocol listens to requests on port 43 
-  Using this information an attacker can create a map of the organization's network
-  sites:
   -  domaintools.com
   -  tomas.com
- ip geolocation information
  - tool:  IP2Location
  
## DNS footprinting
- dns record types PAGE 237
  
## network footprinting

- Network range information assists attackers in creating a map of the target network
- Find the range of IP addresses using ARIN whois database search tool
- You can find the range of IP addresses and the subnet mask used by the target organization from Regional Internet Registry (RIR)
- traceroute:
  - Traceroute programs work on the concept of ICMP protocol and use the TTL field in the header of ICMP packets to discover the routers on the path to a target host
  - Attackers conduct traceroute to extract information about network topology, trusted routers, and firewall locations

## social engineering
- nontechnical
- techniques:
  - eavesdropping
  - shouldersourfing
  - dumpster diving

# Footprinting tools

- Maltego
- Recon-ng:
  -  designed exclusively for web-based open source reconnaissance
- FOCA
- OSRFramework
  -  provide a collection of scripts that can enumerate users, domains, and more across over 200 separate service
  -  usufy.py 
  -  mailfy.py 
  -  searchfy.py 
  -  domainfy.py 
  -  phonefy.py
  -  entify.py

# footprinting countermeasures

Configure IIS to avoid information disclosure through banner grabbing. 
Configure web servers of the target organization  to avoid information leakage. 
Always use TCP/IP and IPSec filters for defense in depth. 
Hide the IP address and the related information by implementing VPN or keeping server behind a secure proxy.

# footprinting penetration testing

-  Footprinting pen testing helps organization to: 
   -   Prevent information leakage 
   - Prevent social engineering attempts 
   -  Prevent DNS record retrieval from publically available servers
   
# Notes

### active vs passive

Passive footprinting involves gathering information about the target without direct interaction. We can only collect the archived and stored information from about the target using publicly accessible sources such as search engines, social networking sites, job sites, groups, forums, and blogs, and so on.
Active footprinting involves gathering information about the target with direct interaction. In active footprinting, we overtly interact with the target network.
Passive footprinting techniques include:

?        Finding information through search engines
?        Finding the Top-level Domains (TLDs) and sub-domains of a target through web services
?        Collecting location information on the target through web services
?        Performing people search using social networking sites and people search services
?        Gathering financial information about the target through financial services
?        Gathering infrastructure details of the target organization through job sites
?        Monitoring target using alert services
Active footprinting involves gathering information about the target with direct interaction. In active footprinting, we overtly interact with the target network.
Active footprinting techniques include:
?        Querying published name servers of the target
?        Extracting metadata of published documents and files
?        Gathering website information using web spidering and mirroring tools
?        Gathering information through email tracking
?        Performing Whois lookup
?        Extracting DNS information
?        Performing traceroute analysis
?        Performing social engineering




