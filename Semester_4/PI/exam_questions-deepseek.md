# Exam Questions - DeepSeek Answers

### Security vs. Privacy & Legal Frameworks (Slides: 1_Intro, Legal Frameworks)

**1. Show areas in which IT security and privacy have conflicting goals**
- **User Tracking:** Security teams may log everything (e.g., in intrusion detection systems) to detect anomalies, but this logs private data. (1_Intro, p. 19)
- **Anonymity:** People want anonymity for privacy, but criminals exploit it to avoid identification. (1_Intro, p. 19)
- **Encryption Backdoors:** Governments want access to chat messages to fight crime, but this breaks the confidentiality and privacy of legitimate users. (1_Intro, p. 20)
- **Biometrics:** Facial recognition provides high security but is intrusive and can be biased. (1_Intro, p. 20)
- **Cloud Computing:** Cloud provides security (backup), but a third party storing data creates privacy and ownership questions. (1_Intro, p. 21)

**2. 8 OECD Privacy Principles (1980)**
1.  **Collection Limitation:** Limits to collecting data; must be lawful and with consent. (Legal Frameworks, p. 6)
2.  **Data Quality:** Data should be relevant, accurate, and up-to-date. (Legal Frameworks, p. 6)
3.  **Purpose Specification:** Purpose must be specified before collection. (Legal Frameworks, p. 6)
4.  **Use Limitation:** Data cannot be disclosed/used for other purposes except with consent or by law. (Legal Frameworks, p. 7)
5.  **Security Safeguards:** Data must be protected against risks like unauthorized access. (Legal Frameworks, p. 7)
6.  **Openness:** Organizations must be open about data collection and processing. (Legal Frameworks, p. 7)
7.  **Individual Participation:** Individuals have rights to obtain, challenge, and have data erased. (Legal Frameworks, p. 8)
8.  **Accountability:** Controllers are accountable for complying with these principles. (Legal Frameworks, p. 8)

**3. Defined Roles in the GDPR**
- **Data Subject:** The "natural person" (EU resident) who owns their personal data. (Legal Frameworks, p. 15)
- **Data Controller:** The organization that collects data and determines the purpose and means of processing. (Legal Frameworks, p. 15)
- **Data Processor:** An organization (e.g., cloud provider) that processes data *on behalf of* the controller. Now has direct obligations under GDPR. (Legal Frameworks, p. 15)
- **Data Protection Officer (DPO):** Appointed by companies doing large-scale monitoring or processing special data; ensures GDPR adherence. (Legal Frameworks, p. 16)
- **Data Protection Authority (DPA):** Each EU member state's national authority that enforces the regulation and issues fines. (Legal Frameworks, p. 16)

**4. “Privacy by Design” strategies**
- **Data Minimization:** Collect only what is necessary ("You cannot lose what you do not have"). (Legal Frameworks, p. 29)
- **Pseudonymisation:** Replace identifiers so data can't be attributed to a subject without additional information (encryption, hashing, masking, aggregation). (Legal Frameworks, p. 30)

**5. The four sections a DPIA must contain (GDPR Art 35:7)**
1.  **Description of the processing activity** (types/amount of data, retention, collection, destruction). (Legal Frameworks, p. 34)
2.  **Description of purpose(s)** (necessity, proportionality, legal basis). (Legal Frameworks, p. 34)
3.  **Description of lawfulness of processing** (compliance with privacy principles like purpose limitation, minimization). (Legal Frameworks, p. 35)
4.  **Identification of risks** to rights/freedoms of individuals (origin, nature, severity). (Legal Frameworks, p. 35)
5.  **Description of measures to mitigate risks** (technical/organizational methods). (Legal Frameworks, p. 35)
6.  **Determination of residual risks** (re-evaluation after measures). (Legal Frameworks, p. 35)

*(Note: The slides list six main components, not four, but these cover the core legal requirements mentioned.)*

### Identity Management (Slides: 2_IdentityManagement, selfSovereignIdentity)

**6. Describe the U-prove interactions between actors**
Actors: User (Holder), Identity Provider (Issuer), Relying Party (Verifier).
1.  **Issuance:** The user sends a blinded public key (`g4^x`) to the issuer. The issuer builds and signs a credential `H = {g1^a1 * g2^a2 * g3^a3 * g4^x}` without knowing `x` (blind signature). (2_IdentityManagement, p. 35-36)
2.  **Showing (Presentation):** The user sends the credential `H` to the RP and proves knowledge of undisclosed attributes using a Zero Knowledge Proof (ZKP), disclosing only required attributes. (2_IdentityManagement, p. 37-38)

**7. Describe the U-prove selective disclosure mechanism**
1.  The RP requests a specific attribute (e.g., `a1`). (2_IdentityManagement, p. 37)
2.  The user sends the requested attribute `{a1}` and a commitment `B = {g2^a2 * g3^a3 * g4^x}`. (2_IdentityManagement, p. 37)
3.  The RP checks if `{g1^a1} * B = H`. (2_IdentityManagement, p. 37)
4.  The user then proves knowledge of the undisclosed attributes (`a2, a3, x`) using a zero-knowledge proof (challenge-response with random values), without revealing them. (2_IdentityManagement, p. 38)

**8. Describe the SSI Architecture**
- **Actors:** Holder, Issuer, Verifier, and a Verifiable Data Registry (blockchain/DLT). (selfSovereignIdentity, p. 9)
- **Core Components:**
    - **DID (Decentralized Identifier):** A permanent address on the ledger that resolves to a DID Document. (selfSovereignIdentity, p. 13)
    - **Verifiable Credentials (VCs):** Cryptographically signed statements by an Issuer, stored in the Holder's wallet (not on the blockchain). (selfSovereignIdentity, p. 18)
    - **Verifiable Presentations (VPs):** Credentials shared by the Holder with a Verifier.
    - **Agents (DIDComm):** Secure, peer-to-peer communication channels between actors. (selfSovereignIdentity, p. 26)

**9. What is the DID designed and used for?**
A Decentralized Identifier (DID) is a **permanent, resolvable, cryptographically verifiable, decentralized identifier**. It is used to:
- Look up a DID Document on the ledger. (selfSovereignIdentity, p. 13)
- Prove ownership/control of an identity using cryptography. (selfSovereignIdentity, p. 14)
- Replace centralized registration authorities. (selfSovereignIdentity, p. 14)

**10. How can we replace the Certification Authority in a decentralized PKI**
- The identifier (DID) is generated **cryptographically from the public key** itself. (selfSovereignIdentity, p. 17)
- The controller binds itself to the identifier because it is the only one that can publish the identifier on the immutable distributed ledger. (selfSovereignIdentity, p. 17)
- This creates a **self-certifying identifier**, eliminating the need for a trusted third-party CA.

**11. Describe the structure of a Verifiable Credential**
1.  **Credential Metadata:** Includes issuer identity, unique ID, issue/expiry dates. (selfSovereignIdentity, p. 21)
2.  **Claims:** The actual information about the subject (e.g., name, DOB, ID number). (selfSovereignIdentity, p. 21)
3.  **Proofs:** Cryptographic elements to verify the issuer's signature, data integrity, and revocation status. (selfSovereignIdentity, p. 21)

**12. Give examples of privacy enhancements in SSI interactions**
- **Selective Disclosure:** Holder can disclose only specific claims (e.g., "over 18") without revealing the birthdate. (selfSovereignIdentity, p. 22)
- **Un-linkability:** The issuer cannot track when/where a credential is presented (holders use a blinded link secret). (selfSovereignIdentity, p. 22-23)
- **Anonymity:** Holder can remain anonymous while verifiably presenting a credential. (selfSovereignIdentity, p. 22)
- **Un-correlation:** Verifiers cannot track if a credential has been presented multiple times. (selfSovereignIdentity, p. 23)

**13. What is a DID document and what does it contain**
A DID document is returned when you "resolve" a DID on the ledger. It is expressed in JSON-LD and contains:
1.  The DID itself. (selfSovereignIdentity, p. 13)
2.  Public keys (for verification). (selfSovereignIdentity, p. 13)
3.  Authentication methods (to prove control). (selfSovereignIdentity, p. 13)
4.  Service endpoints (e.g., for SSI agents). (selfSovereignIdentity, p. 13)
5.  Timestamp (for audit). (selfSovereignIdentity, p. 13)
6.  Signature (for integrity). (selfSovereignIdentity, p. 13)

**14. Which challenges for spreading of SSI have been identified?**
- **Technical complexity** of decentralized identity. (selfSovereignIdentity, p. 28)
- **Integration difficulty** with legacy/federated systems (eIDAS, CAs). (selfSovereignIdentity, p. 28)
- **Key loss:** No password reset for lost private keys. (selfSovereignIdentity, p. 28)
- **High computational load** on mobile devices for ZKPs. (selfSovereignIdentity, p. 28)
- **Scalability bottlenecks** affecting real-time transactions. (selfSovereignIdentity, p. 28)
- **Legal uncertainty** with GDPR (e.g., immutability vs. right to be forgotten). (selfSovereignIdentity, p. 28, 31)
- **Trust delegation:** Defining reliable issuer models. (selfSovereignIdentity, p. 28)

**15. What are the advantages of eIDAS compared to SSI?**
- **Legal Trust:** eIDAS 2.0 provides legal trust, making identities usable in **regulated environments** (finance, healthcare), while SSI lacks this. (selfSovereignIdentity, p. 31)
- **Mandatory Acceptance:** Specified services (large online platforms, financial sector) *must* accept EUDI Wallets. (selfSovereignIdentity, p. 30)
- **Clear Legal Identification:** Requires verified and secure identification (no anonymous self-issued credentials). (selfSovereignIdentity, p. 31)

**16. “in eIDAS2.0 a verified and secure identification is essential” – implications for EU citizens**
This means that unlike pure SSI, a citizen **cannot participate anonymously** in the eIDAS ecosystem. They must first establish their real-world identity through a verified procedure to obtain a government-issued credential. This sets an entry requirement for participation. (selfSovereignIdentity, p. 31)

**17. Which advanced features of SSI will be also available in eIDAS2.0?**
- **W3C Verifiable Credentials** framework. (selfSovereignIdentity, p. 30)
- **Selective disclosure** (share only necessary attributes, e.g., "over 18" without birthdate). (selfSovereignIdentity, p. 30)
- **Cross-border interoperability** (wallets from one member state work in others). (selfSovereignIdentity, p. 30)
- **Qualified Electronic Attestations of Attributes (QEAAs)** for professional qualifications. (selfSovereignIdentity, p. 30)

### Database Privacy (Slide: 6_DB-privacy)

**18. What is the database privacy problem and what should a good solution achieve?**
- **Problem:** Databases (health, finance, AI) contain private information. We need to publish them for secondary research but must protect individuals from re-identification while keeping data accurate. (6_DB-privacy, p. 2)
- **Good solution:** Protect private information, remove re-identification possibility, and keep as much data accuracy as possible. (6_DB-privacy, p. 2)

**19. What are Local and Global differential privacy?**
- **Local DP:** Noise is added to **each data point** *before* it enters the database. Protects against untrusted database owner. (6_DB-privacy, p. 30, 37)
- **Global DP:** The database contains raw data. Noise is added **only to the query result**. Requires trust in the database owner. (6_DB-privacy, p. 30, 31)

**20. What does Differential Privacy guarantee?**
It guarantees that an adversary cannot tell if any single individual's data has been changed, added, or removed from the dataset. The behavior of the algorithm remains roughly unchanged regardless of whether any one person's data is included. (6_DB-privacy, p. 19, 36, 39)

**21. How do we calculate the sensitivity of a query?**
Sensitivity is the **maximum distance** between the result of a query on the original database and the result of the same query on any "neighbor" database (a database with one single row removed). (6_DB-privacy, p. 25, 26)
- For a `sum` query on a `[0,1]` database, sensitivity = 1. (6_DB-privacy, p. 26)

**22. What is epsilon and how is it related to the amount of Laplacian noise**
- **Epsilon (ε)** is the **privacy loss parameter**. A smaller ε means stronger privacy. (6_DB-privacy, p. 31)
- **Noise amount (β)** is calculated as: `β = sensitivity / ε`. (6_DB-privacy, p. 31)
- **Relationship:** Smaller ε → larger β (more noise) → stronger privacy but less accuracy. Larger ε → smaller β (less noise) → weaker privacy but higher accuracy. (6_DB-privacy, p. 31)

### Tracking (Slides: Tracking(Collecting), Tracking(processing))

**23. Describe tracking methods that use storage at the user (browser, etc)**
- **Standard HTTP Cookies:** Server sets a cookie (e.g., `Set-Cookie: SID=...`), browser returns it. (Tracking-Collecting, p. 9)
- **Third-party cookies:** Ad content from a third party sets a cookie, allowing tracking across different first-party websites. (Tracking-Collecting, p. 10)
- **History Sniffing:** Exploits CSS `:visited` styling or timing to see which URLs a user has visited. (Tracking-Collecting, p. 11-12)
- **ETags (Entity Tags):** Server stores a unique, persistent hash in the browser cache, used for tracking even if cookies are deleted. (Tracking-Collecting, p. 15-16)
- **Evercookies:** Uses multiple browser storage mechanisms (Flash, HTML5, etc.) to recreate a deleted cookie. (Tracking-Collecting, p. 17)

**24. Describe how cookie-less tracking works.**
It creates a **server-side ClientID** when consent is given (first-party cookie) or by hashing the user's IP address, user agent, and website URL. Methods include:
- **Event tracking** (page views, clicks). (Tracking-Collecting, p. 19)
- **Server log analysis** (IP, user agent). (Tracking-Collecting, p. 19)
- **API tracking** (from social media/mobile apps). (Tracking-Collecting, p. 19)

**25. How is browser fingerprinting used & how to avoid it?**
- **How it works:** Collects data from the browser (User Agent, HTTP headers, screen resolution, timezone, plugins, fonts) to create a unique identifier. 83% of browsers have a unique fingerprint. (Tracking-Collecting, p. 20-21)
- **Avoidance:**
    - Use **Tor Browser** or **NoScript** (Firefox). (Tracking-Collecting, p. 22)
    - Use **Brave browser** (adds subtle noise to fingerprinting APIs). (Tracking-Collecting, p. 22)

**26. How do search engines threaten our privacy?**
- **Search terms** disclose thoughts, problems, intelligence, and knowledge. (Tracking-Collecting, p. 29)
- **Search date/time** discloses work/leisure rhythm. (Tracking-Collecting, p. 29)
- **IP address** discloses location and links all searches of the same user. (Tracking-Collecting, p. 29)
- Example: The 2006 AOL database disclosure published 3 months of search records for 658,000 "anonymized" users. (Tracking-Collecting, p. 30)

**27. How does predictive analytics work? Give 3 application scenarios.**
- **How it works:** Uses data mining (cluster analysis, classification, association) and machine learning on Big Data to find correlations and predict behavior rather than causality. (Tracking-Processing, p. 3, 4)
- **Scenarios:**
    1.  **Politics:** Predict how people will vote. (Tracking-Processing, p. 18)
    2.  **Credit worthiness:** Predict if a person will pay back debt (e.g., Zest Finance uses 70,000 signals). (Tracking-Processing, p. 18, 19)
    3.  **Health:** Predict risks for illnesses (e.g., Aviva predicts diabetes, blood pressure from consumption data). (Tracking-Processing, p. 18, 20)

**28. How can tracking data be used in predicting health, fitness, car insurance fees?**
- **Health/Fitness (Fitbit):** Tracks steps, sleep, heart rate, calories. Business model: Sells data to employers, who pay less to insurers based on employee goal achievement. (Tracking-Processing, p. 21)
- **Car Insurance (Telematics box):** Box records time of day driven, speed, braking/acceleration, motorway miles, total mileage. Used to assess risk, calculate renewal premium, and reward safe drivers. (Tracking-Processing, p. 22-24)

**29. Social Bots: how do they work, impacts?**
- **How they work:** Fake user accounts run by code. Can be bought cheaply ($0.50). A bot farm manager buys bots, programs interactions (e.g., likes, comments, conversations). (Tracking-Processing, p. 26, 27)
- **Impacts:**
    - **Users:** Manipulate opinions, spread false narratives, classify users (dumb/smart) based on reactions, create echo chambers. (Tracking-Processing, p. 29, 31)
    - **Companies:** Fake marketing engagement. (Tracking-Processing, p. 27)
    - **Governments:** Election manipulation (e.g., 2020 US, Brexit, 2025 Germany), foreign interference. (Tracking-Processing, p. 31)

### Network & Location Privacy (Slides: Location_Vehicular)

**30. Explain the main differences between a TOR network and a mix.**
- **Latency:** Tor is **low-latency** (< 1 sec); Mixes are **high-latency** (collect and hold messages). (Location_Vehicular, p. 13, 20)
- **Operation:** Tor uses **onion routing** (reroutes packets but does not reorder/delay). Mixes **reorder, delay, and mix** messages before sending. (Location_Vehicular, p. 10, 20)
- **Protection Level:** Tor protects against local observers. Mixes (e.g., threshold/timed) protect against a **global observer** controlling all network interfaces. (Location_Vehicular, p. 25)
- **Attack Vulnerability:** Tor is vulnerable to traffic analysis. Mixes use reordering to defeat it. (Location_Vehicular, p. 3, 20)

**31. Threats from collecting user location**
- **Link identity to a car (identifier)** over long periods (cars are personal devices). (Location_Vehicular, p. 41)
- **Track a specific vehicle's** past, present, and future locations. (Location_Vehicular, p. 29)
- **"Big Brother" surveillance:** Scan environment, spy on private/secured locations without consent. (Location_Vehicular, p. 41)
- **Cheat vehicles with fake messages** (e.g., bogus traffic jam, fake speed/identity to hide accident involvement). (Location_Vehicular, p. 41)

### AI Act & ML Privacy (Slides: the EU AI Act and privacy protection in machine learning)

**32. Forbidden AI applications mentioned in the AI Act**
1.  Social scoring systems. (EU AI Act, p. 5)
2.  Emotion recognition at work/school (except medical/safety). (EU AI Act, p. 5)
3.  Exploiting vulnerabilities (age, disability). (EU AI Act, p. 5)
4.  Untargeted scraping of facial images for databases. (EU AI Act, p. 5)
5.  Biometric identification based on sensitive characteristics. (EU AI Act, p. 5)
6.  Law enforcement use of real-time remote biometric ID in public. (EU AI Act, p. 5)

**33. Main high risk areas mentioned in the AI Act**
1.  Biometrics (if permitted by law). (EU AI Act, p. 7)
2.  Critical infrastructure (road traffic, water, gas, electricity). (EU AI Act, p. 7)
3.  Education & vocational training (access, evaluation, monitoring). (EU AI Act, p. 8)
4.  Employment & worker management (recruitment, promotions, termination). (EU AI Act, p. 9)
5.  Essential services & benefits (credit scoring, insurance, emergency dispatch). (EU AI Act, p. 10)
6.  Law enforcement (risk assessment, polygraphs, evidence reliability). (EU AI Act, p. 11)
7.  Migration & border control (risk assessment, visa applications). (EU AI Act, p. 12)
8.  Administration of justice & democratic processes (interpreting facts/law, influencing elections). (EU AI Act, p. 13)

**34. Why is privacy important in machine learning?**
We need ML algorithms that do **not memorize sensitive information about the training set** (e.g., specific medical histories of individual patients). Differential privacy provides a framework to measure the privacy guarantees of an ML algorithm. (EU AI Act, p. 21)

**35. What is federated learning architecture and how can it better protect personal data?**
- **Architecture:** Instead of centralizing data, models are trained **locally on users' devices** (or separate silos like hospitals). Only the model updates (e.g., gradients, labels) are shared, not the raw data. (EU AI Act, p. 18, 22)
- **Privacy protection:** Raw private data never leaves the local device/institution. An example is the **PATE framework** (Private Aggregation of Teacher Ensembles), where multiple teacher models (from different hospitals) label new data, and a student model learns from the aggregated, noisy labels. (EU AI Act, p. 22-26)
