# PFS-SPAKE2


## Introduction to PAKE protocols. 
Password-based Authenticated Key-Exchange (PAKE) protocols allow two users, who only share a password, to mutually authenticate each other and agree on a high entropy session key. Thus, the permit the establishment of **secure communications** (authenticated and encrypted). Theoretically they are fascinating, because of their ability to use a weak secret – such as a password or a pin – to produce a strong cryptographic key in a provably secure fashion over an insecure network. They may also be merely used as user authentication mechanism, for instance in login scenarios. 

It is worth noting one of the beauties of PAKEs: **the password is intrinsically protected**. In particular, the password is never transmited in clear (an eavesdroper observing the protocol execution will not get any information regardig the users's pasword). This is known as off-line dictionary attack resistance.  Additionally, an active adversary trying to impersonate a user will only be able to test one password per protocol execution (so far this is unavoidable in any authentication mechanism, however, an easy countermeasure is blocking the underlying user account after a number of failed login attemps).    

This project is a python implementation of the PFS-SPAKE2 protocol which provably satisfies the perfect-forward secrecy property [link to published paper here](https://eprint.iacr.org/2019/351.pdf). 

### Implementation Requirements.
This implementation is done in python3 using mostly standard libraries. The only extra crypto library needed is [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html).

### Execution
1. python3 main.py
2. Follow the instructions. Make sure the password is the same for both users (it is a shared password).

### Security Considerations.
   1. This implementation permits the selection of three security levels: 103, 125 or 150 bits of security. 
   2. The cryptographic groups used are standarized and recommended by [NIST](https://csrc.nist.gov/CSRC/media/Publications/sp/800-56a/rev-3/draft/documents/sp800-56ar3-draft.pdf) and [IETF](https://tools.ietf.org/html/rfc7919#section-8.3).
   3. Side-channel attacks, e.g. timing attacks are not considered. 
   
Matthew Green has a nice overview of PAKE protocols (and its great benefits vs the traditional password-over-TLS approach) here [link](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/).
