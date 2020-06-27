# SQL injection concepts

- SQL injection attacks do not exploit a specific software vulnerability, instead they target websites and web apps that do not follow secure coding practices for accessing and manipulating data stored in a relational database

# types of SQL injections 

- In-band SQL Injection:
  -  An attacker uses the same communication channel to perform the attack and retrieve the results. In-band attacks are commonly used and easy-to-exploit SQL injection attacks. Most commonly used in-band SQL injection attacks are error-based SQL injection and UNION SQL injection.
     -  Error-Based SQL Injection 
        -   forces the database to perform some operation in which the result will be an error 
     -  System Stored Procedure 
     -  Illegal/Logically Incorrect Query 
     -  UNION SQL Injection
     -  Tautology
     -  End-of-Line Comment
     -  In-line Comments
     -  Piggybacked Query
- Blind/Inferential SQL Injection:
  - the attacker has no error messages from the system with which to work. Instead, the attacker simply sends a malicious SQL query to the database. This type of SQL injection takes longer time to execute because the result returned is generally in the form of boolean. Attackers use the true or false results to know the structure of the database and the data. In case of inferential SQL injection, no data is transmitted through the web application, and it is not possible for an attacker to retrieve the actual result of the injection; therefore, it is called blind SQL injection.
    - Time-based SQL injection
      - evaluates the time delay that occurs in response to true or false queries sent to the database. A waitfor statement stops SQL Server for a specific amount of time. Based on the response, an attacker will extract information such as connection time to the database made as the system administrator or as other users and launch further attacks
    - Boolean Exploitation
      - Multiple valid statements that evaluate true and false are supplied in the affected parameter in the HTTP request
      - By comparing the response page between both conditions, the attackers can infer whether or not the injection was successful
    - Heavy Query
      - Attackers use heavy queries to perform time delay SQL injection attack without using time delay functions
      - Heavy query retrieves a huge amount of data and takes a huge amount of time to execute on the database engine
      - Attackers generate heavy queries using multiple joins on system tables



- Out-of-Band SQL Injection: 
  - Attackers use different communication channels (such as database email functionality, or file writing and loading functions) to perform the attack and obtain the results. This type of attack is difficult to perform because the attacker needs to communicate with the server and acquire features of the database server used by the web application
  - In Out-of-Band SQL injection, the attacker needs to communicate with the server and acquire features of the database server used by the web application
  - Attackers use different communication channels to perform the attack and obtain the results
  - Attackers use DNS and HTTP requests to retrieve data from the database serverver
  - For example, in Microsoft SQL Server, an attacker exploits xp_dirtree command to send DNS requests to a server controlled by the attacker

# SQL Injection Methodology

###  Information Gathering and SQL Injection Vulnerability Detection
  1. Check if the web application connects to a Database Server in order to access some data 
  2. List all input fields, hidden fields, and post requests whose values could be used in crafting an SQL query
  3.  Attempt to inject codes into the input fields to generate an error 
  4.  Try to insert a string value where a number is expected in the input field 
  5.  Use UNION operator to combine the result-set of two or more SELECT statements 
  6.  Check the detailed error messages for a wealth of information in order to execute SQL injection 
- Identifying Data Entry Path 
  - using Burp Suite and Tamper DAta
-  Testing for SQL Injection 
   -  There are standard SQL injection inputs called testing strings used by an attacker to perform SQL injection attacks.
- Additional Methods to Detect SQL Injection 
  - Function Testing 
  - Fuzzing Testing 
  - static/dynamic testing
- SQL Injection Black Box Pen Testing
  -  Detecting SQL Injection Issues 
  -    Detecting Input Sanitization
       -  Use right square bracket (the ] character) as the input data to catch instances where the user input is used as part of an SQL identifier without any input sanitization
  -   Detecting Truncation Issues 
      -   Send long strings of junk data, just as you would send strings to detect buffer overruns; this action might throw SQL errors on the page
  -  detecting  SQL Modification
- Source Code Review to Detect SQL Injection Vulnerabilities
- An attacker can identify blind SQL injection vulnerabilities just by testing the URLs of a target website

### Launch SQL Injection Attacks

- Perform Union SQL Injection 
  -  use ORDER BY to find the columns, and at the end, they use the UNION ALL SELECT command. 
- Perform Error Based SQL Injection
- Perform Error Based SQL Injection using Stored Procedure Injection
- Bypass Website Logins Using SQL Injection 
  - Try these at website login forms: 
    - admin' --
    - admin' # 
    - admin'/* 
    - ' or 1=1--
    - ' or 1=1# 
    - ' or 1=1/* 
    - ') or '1'='1--
    -  ') or ('1'='1--
- Perform Blind SQL Injection—Exploitation (MySQL) 
  - find first character 97=a
- Bypass Firewall using SQL Injection
### Advanced SQL Injection
- Database, Table, and Column Enumeration
-  Transfer Database to Attacker's Machine
-  Creating Server Backdoors using SQL Injection

# Evasion Techniques 
- In-line Comment: 
  - Obscures input strings by inserting in-line comments between SQL keywords.
- Char Encoding: 
  - Uses built-in CHAR function to represent a character. 
- String Concatenation: 
  - Concatenates text to create SQL keyword using DB specific instructions.
- Obfuscated Codes: 
  - Obfuscated code is an SQL statement that has been made difficult to understand.
- Manipulating White Spaces: 
  - Obscures input strings by dropping white space between SQL keyword.
- Hex Encoding: 
  - Uses hexadecimal encoding to represent a SQL query string. 
-  Sophisticated Matches:
   -   Uses alternative expression of ”OR 1=1”. 
-  URL Encoding:
   -   Obscure input string by adding percent sign ‘%’ before each code point. 
-  Case Variation: 
   -  Obfuscate SQL statement by mixing it with upper case and lower case letters.
-   Null Byte: 
    -   Uses null byte (%00) character prior to a string in order to bypass detection mechanism.
-   Declare Variables: 
    -   Uses variable that can be used to pass a series of specially crafted SQL statements and bypass detection mechanism.
-    IP Fragmentation:
     - Uses packet fragments to obscure attack payload which goes undetected by signature mechanism.

# Countermeasures

- Why are Web Applications Vulnerable to SQL Injection Attacks? 
  -  The database server runs OS commands 
  - Using privileged account to connect to the database
  -  Error message revealing important information
  - no data validation at the server 
  - Minimizing Privileges
  - Implementing Consistent Coding Standards
  - Firewalling the SQL Server 
-  Some of the expressions that can be blocked by the Snort are as follows:
-     /(\%27)|(\')|(\-\-)|(\%23)|(#)/ix 
-     /exec(\s|\+)+(s|x)p\w+/ix 
-      /((\%27)|(\'))union/ix 
-      /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix 
-      alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - Paranoid"; flow:to_server,established;uricontent:".pl";pcre:"/(\%27)|( \')|(\-\-)|(%23)|(#)/i"; classtype:Web-application-attack; sid:9099; rev:5





