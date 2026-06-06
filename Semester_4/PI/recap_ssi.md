# Recap SSI

## SSI Questions

**1. Describe the SSI Architecture**

The SSI architecture consists of three main actors — Issuer, Holder, and Verifier — plus a Verifiable Data Registry (VDR), which is a distributed ledger/blockchain. The Issuer creates and issues Verifiable Credentials to the Holder. The Holder stores these in a digital wallet (on a mobile device or encrypted in the cloud) and generates Verifiable Presentations to send to Verifiers. All actors interact with the VDR to register or look up identifiers, public keys, schemas, and credential definitions. Communication happens peer-to-peer via DIDComm protocols. The architecture also includes an Edge Layer (edge agents/wallets on user devices) and a Cloud Layer (cloud agents/wallets), sitting above the DID Layer (the ledger).

→ *Found on: Slides 11–12*

---

**2. What is the DID designed and used for?**

A Decentralized Identifier (DID) is a permanent address on the ledger. It has four key properties: it is persistent (doesn't need to change), resolvable (looking it up returns a DID document with metadata), cryptographically verifiable (you can prove ownership using cryptography), and decentralized (no centralized registration authority is needed). When resolved, a DID returns a DID document in JSON-LD containing the DID itself, a public key, an authentication method, service endpoints, a timestamp, and a signature. DIDs provide the global infrastructure for accessing issuers and verifiers in SSI.

→ *Found on: Slides 13–14*

---

**3. How can we replace the Certification Authority in a decentralized PKI?**

In traditional PKI, a Certification Authority (CA) acts as a trusted third party to bind a public key to a controller's identity via a signed certificate. In SSI, this is replaced by the distributed ledger. The DID identifier is generated cryptographically from the public key itself, meaning the controller binds itself to the identifier since only they can publish it. The ledger serves as a decentralized PKI that is immutable by design, eliminating the need for a trusted third party. This also solves the key rotation problem.

→ *Found on: Slides 15–17*

---

**4. Describe the structure of a Verifiable Credential**

A Verifiable Credential has three core components: (1) **Credential Metadata** — general information such as the issuer's identity, the credential's unique ID, and issue/expiry dates, often cryptographically signed by the issuer; (2) **Claims** — the actual tamper-proof assertions about the subject (e.g., full name, date of birth, ID number); and (3) **Proofs** — the cryptographic elements that let verifiers confirm the credential was issued by a trusted party, hasn't been altered, and is still valid (not expired or revoked).

→ *Found on: Slide 21*

---

**5. Give examples of privacy enhancements in the interactions holder, issuer, verifier**

Key privacy enhancements include: selective disclosure (holders can choose which specific claims to reveal using ZKP techniques), anonymity (holders can present credentials while maintaining their anonymity), un-linkability (issuers cannot track how or where a credential is presented), tamper-evidence (verifiers can detect alterations), and un-correlation via a blinded link secret. The blinded link secret ensures that: the identifier an issuer receives can't be correlated with identifiers from other issuers; verifiers receive proof of the link secret without a correlatable identifier; holders can prove multiple credentials are bound to the same secret without revealing a correlatable ID; and holders provide proof of issuer signatures without revealing the signatures themselves.

→ *Found on: Slides 22–23*

---

**6. Where is a DID document stored and what does it contain?**

A DID document is stored on the distributed ledger (blockchain). It contains: the Decentralized Identifier (DID) itself, public cryptographic keys (used to verify credential signatures), credential schemas and revocation registries, and service points (used to look up a DID and connect to peer agents). Importantly, the actual Verifiable Credentials (containing personal data) are **not** stored on the blockchain — they are stored in the user's digital identity wallet.

→ *Found on: Slides 13, 18*

---

**7. What is the difference between the credential schema and the credential definition?**

A **schema** defines the structure of a credential — it is a document written to the ledger specifying attribute names, version, etc. Schemas are immutable; to update one, a new version must be created. A **credential definition** is issuer-specific: each issuer posts one to declare which schema they will use, which signing keys they will employ, and what revocation strategy they follow. The credential definition helps verifiers prove that a credential hasn't been tampered with. In short, the schema defines *what* data a credential contains, while the credential definition declares *how* a specific issuer will issue and sign credentials based on that schema.

→ *Found on: Slide 19*

---

**8. Which challenges for spreading of SSI have been identified?**

The identified challenges include: technical complexity of decentralized identity; legal and architectural integration with legacy/federated identity systems, eIDAS, and CAs; secure protection of private keys (no equivalent of a password reset if a key is lost); high computational load on mobile devices for privacy-preserving disclosure; scalability and performance bottlenecks potentially impacting real-time transactions; the need for secure and redundant credential storage; trust delegation issues (preventing centralization of issuers); legal uncertainty regarding GDPR compliance blocking adoption in finance and healthcare; and revocation and lifecycle management challenges.

→ *Found on: Slide 28*

---

## eIDAS 2.0 Questions

**9. What are the advantages of eIDAS compared to SSI?**

eIDAS 2.0 provides legal trust that SSI alone cannot — for the first time, self-sovereign identities gain legal recognition and become usable in regulated environments. Unlike pure SSI, eIDAS requires a trustworthy third party, which ensures legally compliant identification of all parties. It supports centralized digital identities needed in regulated industries. It also addresses SSI's DLT weakness: the distributed ledger lacks clear legal identification of network participants and may contradict GDPR due to its immutability. eIDAS provides the legal framework and governance that SSI needs to function in real-world regulated contexts.

→ *Found on: Slides 31–32*

---

**10. What does "in eIDAS 2.0 a verified and secure identification is essential" imply for EU residents?**

This means that all EU citizens will need to undergo a verified identification process to participate in the eIDAS ecosystem. This sets an entry requirement — people must first prove their identity through a secure, government-backed process before they can use the EU Digital Identity Wallet. By 2027, all Member States must provide free EUDI Wallets with government-verified credentials. Very large online platforms (like Google, Facebook) and critical infrastructure providers (financial sector, utilities, healthcare) must accept these wallets for strong authentication.

→ *Found on: Slides 30–31*

---

**11. Which advanced features of SSI will also be available in eIDAS 2.0?**

eIDAS 2.0 integrates W3C Verifiable Credentials and selective disclosure capabilities, enabling users to share only necessary attributes (e.g., proving you are over 18 without revealing your birthdate). It also introduces Qualified Electronic Attestations of Attributes (QEAAs) for trusted verification of professional qualifications and corporate roles. Cross-border interoperability is ensured through the Architecture Reference Framework (ARF). Overall, the SSI principles are not fundamentally contradicted by eIDAS 2.0 — rather, eIDAS makes SSI principles a reality while restraining decentralization to an acceptable level for legal trust.

→ *Found on: Slides 30, 32–33*
