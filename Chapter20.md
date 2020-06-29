# concepts

- SHA-1 
  -  a 160-bit hash function that resembles the former MD5 algorithm developed by Ron Rivest. It produces a 160-bit digest from a message with a maximum length of (264 − 1) bits. It was designed by the National Security Agency (NSA) to be part of the digital signature algorithm (DSA) and is most commonly used in security protocols such as PGP, TLS, SSH, and SSL. As of 2010, SHA-1 is no longer approved for cryptographic use because of cryptographic weaknesses.
- MD5
  -  can be cracked by brute-force attack and suffers from extensive vulnerabilities. 
- RC4 
  - is ideal for software implementation.
  - RC4 is a variable key-size symmetric-key stream cipher with byte-oriented operations and it depends on the use of a random permutation. According to some analyses, the period of the cipher is likely to be greater than 10,100. Each output byte uses 8–16 system operations, meaning the cipher has the ability to run fast when used in software. Products like RSA SecurPC use this algorithm for file encryption. RC4 enables safe communications such as traffic encryption (which secures websites) and for websites that use the SSL protocol.
-  MD4 
   -  is used to verify data integrity through the creation of a 128-bit message digest from data input.
- PGP (pretty good privacy) i
  - s a protocol used to encrypt and decrypt data that provides authentication and cryptographic privacy. It is often used for data compression, digital signing, encryption and decryption of messages, e-mails, files, directories, and to enhance privacy of e-mail communications. The algorithm used for message encryption is RSA for key transport and IDEA for bulk-message encryption. PGP uses RSA for computing digital signatures and MD5 for computing message digests. PGP combines the best features of both conventional (about 1,000 times faster than public-key encryption) and public-key cryptography (solution to key distribution and data transmission issues) and is therefore known as hybrid cryptosystem.
- DES
  -  is a standard for data encryption that uses a secret key for both encryption and decryption (symmetric cryptosystem). 3DES does DES three times with three different keys. 3DES uses a “key bundle” that comprises three DES keys, K1, K2, and K3. Each key is standard 56-bit DES key.

### chipers

- Classical ciphers:
  -  Classical ciphers are the most basic type of ciphers, which operate on alphabets (A-Z). Implementation of these ciphers is generally either by hand or with simple mechanical devices. 
- Block ciphers: 
  - Block ciphers determine algorithms operating on a block (group of bits) of fixed size with an unvarying transformation specified by a symmetric key. 
- Modern ciphers: 
  - The user can calculate the Modern ciphers with the help of a one-way mathematical function that is capable of factoring large prime numbers.
- Stream ciphers: 
  - Symmetric key ciphers are plaintext digits combined with a key stream (pseudorandom cipher digit stream). Here, the user applies the key to each bit, one at a time. Examples include RC4, SEAL, etc.

# PKI

- CA
  - A certificate authority can issue multiple certificates in the form of a tree structure. A root certificate is the top-most certificate of the tree; the private key that is used to “sign” other certificates. All certificates signed by the root certificate, with the "CA" field set to true, inherit the trustworthiness of the root certificate – a signature by a root certificate is somewhat analogous to “notarizing” an identity in the physical world. Such a certificate is called an intermediate certificate or subordinate CA certificate. Certificates further down the tree also depend on the trustworthiness of the intermediates.
- Validation authority and registration authority are the components of public key infrastructure. 
- A self-signed certificate 
  - is an identity certificate signed by the same entity whose identity it certifies. 
  -  are widely used for testing purposes. In self-signed certificates, a user creates a pair of public and private keys using a certificate creation tool such as Adobe Reader, Java’s keytool, Apple's Keychain, and so on and signs the document with the public key. Th
  -  e receiver requests the sender for the private key to verify the certificate.
- signed certificates, certification authorities (CAs) sign and issue signed certificates. These certificates contain a public key and the identity of the owner. The corresponding private key is kept secret by the CA. By issuing the certificate, the CA confirms or validates that the public key contained in the certificate belongs to the person, company, server, or other entity mentioned in the certificate. CA verifies an application’s credentials; thus, users and relying parties trust the information in the CA’s certificates. The CA takes accountability for saying, “Yes, this person is who they state they are, and we, the CA, certify that.” Some of the popular CAs include Comodo, IdenTrust, Symantec, and GoDaddy.

- A man-in-the-middle attack (MITM) is an attack where the attacker secretly relays and possibly alters the communication between two parties who believe they are directly communicating with each other. PKI certificates can be used to encrypt traffic between a client and the server. In this scenario, even if an attacker successfully sniffs the network, it will be difficult to decode the authentication tokens or cookies required for a MITM attack.

- Both server and client certificates encompass the “Issued to” section. Here, for server certificate the “Issued to” section’s value will be the hostname for which it has to be issued and for the client certificate, it will be the user identity or the user name. Both client and server certificates are a significant indication for trust and safe transactions or accessing a website. 

- PKI uses public-key cryptography, which is widely used on the Internet to encrypt messages or authenticate message senders. In public-key cryptography, a CA simultaneously generates a public and private key with the same algorithm. The private key is held only by the subject (user, company, or system) mentioned in the certificate, while the public key is made publicly available in a directory that all parties can access. The subject keeps the private key a secret and uses it to decrypt the text encrypted by someone else using the corresponding public key (available in a public directory). This way, others encrypt messages for the user with the user’s public key, and the user decrypts it with his/her private key.

### PKI components

- Validation authority (VA):
  -  Stores certificates (with their public keys)
- Certificate authority (CA): 
  - Issues and verifies digital certificates
- Registration authority (RA): 
  - Acts as the verifier for the certificate authority
- End user: 
  - Requests, manages, and uses certificates

# attacks

- Birthday attack: 
  - A birthday attack is a name used to refer to a class of brute-force attacks against cryptographic hashes that makes the brute forcing easier. The birthday attack depends on birthday paradox. Birthday paradox is the probability that two or more people in a group of 23 share the same birthday is greater than 1/2.

- Known plaintext attack: 
  - In this cryptanalysis attack, the only information available to the attacker is some plaintext blocks along with corresponding ciphertext and algorithm used to encrypt and decrypt the text. Using this information, the key used to generate ciphertext that is deduced so as to decipher other messages.

- Meet-in-the-middle attack:
  -  A meet-in-the-middle attack is the best attack method for cryptographic algorithms using multiple keys for encryption. This attack reduces the number of brute force permutations needed to decode text encrypted by more than one key and conducted mainly for forging signatures on mixed type digital signatures. A meet-in-the-middle attack uses space–time tradeoff; it is a birthday attack, because it exploits the mathematics behind the birthday paradox. It takes less time than an exhaustive attack. It is called a meet-in-the-middle attack, because it works by encrypting from one end and decrypting from the other end, thus meeting “in the middle.”

- Chosen ciphertext attack: 
  - In this cryptanalysis attack, an attacker obtains the plaintexts corresponding to an arbitrary set of ciphertexts of his own choice. Using this information, the attacker tries to recover the key used to encrypt the plaintext.

- Timing attack: 
  - It is based on repeatedly measuring the exact execution times of modular exponentiation operations. The attacker tries to break the ciphertext by analyzing the time taken to execute the encryption and decryption algorithm for various inputs. In a computer, the time taken to execute a logical operation may vary based on the input given. The attacker by giving varying inputs tries to extract the plaintext.
- replay attack: 
  - In a replay attack, packets and authentication tokens are captured using a sniffer. After the relevant info is extracted, the tokens are placed back on the network to gain access. The attacker uses this type of attack to replay bank transactions or other similar types of data transfer, in the hope of replicating and/or altering activities, such as banking deposits or transfers.
- Chosen-plaintext attack: 
  - Chosen plaintext attack is a very effective type of cryptanalysis attack. In this attack, the attacker obtains the ciphertexts corresponding to a set of plaintexts of his own choosing. This can allow the attacker to attempt to derive the key used and thus decrypt other messages encrypted with that key. Basically, since the attacker knows the plaintext and the resultant ciphertext, he has a lot of insight into the key used. This technique can be difficult but is not impossible.
- The circumstances by which an attacker may obtain ciphertexts for given plaintexts are rare. However, modern cryptography is implemented in software or hardware and is used for a diverse range of applications; for many cases, a chosen-plaintext attack is often very feasible. Chosen-plaintext attacks become extremely important in the context of public key cryptography, where the encryption key is public and so attackers can encrypt any plaintext they choose.
- Differential cryptanalysis 
  - is a form of cryptanalysis applicable to symmetric key algorithms. It is the examination of differences in an input and how that affects the resultant difference in the output. It originally worked only with chosen plaintext. It can also work only with known plaintext and ciphertext.
-  DUHK (don't use hard-coded keys) attack 
   -  is a cryptographic vulnerability that allows attackers to obtain encryption keys used to secure VPNs and web sessions. This attack mainly affects any hardware/software using ANSI X9.31 random number generator (RNG). The pseudorandom number generators (PRNGs) generate random sequences of bits based on the initial secret value called a seed and the current state. The PRNG algorithm generates cryptographic keys that are used to establish a secure communication channel over VPN network. In some cases, the seed key is hardcoded into the implementation. Both the factors are the key issues of DUHK attack as any attacker could combine ANSI X9.31 with the hard coded seed key to decrypt the encrypted data sent or received by that device.