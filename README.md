# dkimsc4n
Asynchronous wordlist based DKIM scanner

*Useful during bug bounty hunting or read teaming to find insufficient DKIM records with RSA 512-bit keys*

**CWE-326: Inadequate Encryption Strength**

**Insufficient DKIM record with RSA 512-bit key used**

[![asciicast](https://asciinema.org/a/243588.svg)](https://asciinema.org/a/243588)

### What is DomainKeys Identified Mail (DKIM) ?

DKIM allows the receiver to check that an email claimed to have come from a specific domain was indeed authorized by the owner of that domain. It achieves this by affixing a digital signature, linked to a domain name, to each outgoing email message. The recipient system can verify this by looking up the sender's public key published in the DNS.

### Length of the Key

With rapidly increasing processing power of computers, RSA keys with a 512-bit length, previously considered to be secure, can be cracked in a short period of time. Today, a minimum of 1024 bit RSA should be used. Organizations like the American National Institute of Standards and Technology (NIST) go further, and recommend a minimum of 2048 bits.

### Short key vulnerability

According to RFC 6376 the receiving party must be able to validate signatures with keys ranging from 512 bits to 2048 bits, thus usage of keys shorter than 512 bits might be incompatible and shall be avoided. The RFC 6376 also states that signers must use keys of at least 1024 bits for long-lived keys, though long-livingness is not specified there.

### Exploitation

A 512-bit RSA key is insecure, as was proved in 1998. Nowadays a 512-bit integers can be factored in only a few hours, for less than $100 of compute time in a public cloud environment: https://github.com/eniac/faas

An attacker therefore might be able to obtain private key for said DKIM record and sign any emails for the associated domain. 

### Historical reports

I wasn't able to find any related bug bounty reports, but the same problem was reported to Google back in 2012: https://www.wired.com/2012/10/dkim-vulnerability-widespread

### Impact

An attacker can obtain 512-bit RSA private key from DKIM record and use it to sign spoofed e-mails. This can lead to more sufficient phishing campaigns.
