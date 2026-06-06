# Recap of the EU AI Act and Differential Privacy in Machine Learning

**1. Forbidden AI applications mentioned in the AI Act**

The EU AI Act explicitly prohibits several AI practices deemed to pose unacceptable risk. These include social scoring systems that classify individuals based on social behavior, emotion recognition in workplaces and educational institutions (unless used for medical or safety purposes), AI that exploits people's vulnerabilities such as age or disability, untargeted scraping of facial images from the internet or CCTV for building facial recognition databases, biometric identification systems based on sensitive characteristics, and real-time remote biometric identification by law enforcement in public spaces. (Slide 5)

---

**2. Main high-risk areas mentioned in the AI Act**

An AI system is considered high-risk when it serves as a safety component of a product or is itself a product that requires third-party conformity assessment. (Slide 6)

The eight high-risk domains defined in Annex III are: biometrics, including remote biometric identification, categorisation, and emotion recognition (slide 7); critical infrastructure such as digital systems, road traffic, and utilities (slide 7); education and vocational training, covering admissions, learning evaluation, and exam monitoring (slide 8); employment and worker management, including recruitment, filtering applications, and performance-based contract decisions (slide 9); access to essential public and private services like healthcare eligibility, credit scoring, insurance risk assessment, and emergency call classification (slide 10); law enforcement tools such as risk assessment, polygraphs, evidence evaluation, and profiling (slide 11); migration, asylum, and border control, including risk assessment of persons entering the EU and examination of visa or asylum applications (slide 12); and administration of justice and democratic processes, including AI used to assist judicial authorities or to influence elections (slide 13).

---

**3. Why is privacy important in machine learning?**

In many ML applications, particularly sensitive ones like medical diagnosis, algorithms must not memorize private information from the training data, such as individual patients' medical histories. Without proper safeguards, trained models risk leaking details about specific individuals whose data was used during training. Differential privacy provides a framework for measuring and ensuring the privacy guarantees of such algorithms. (Slides 21–22)

---

**4. Ways to reduce total noise while maintaining differential privacy in the hospital example**

In the federated learning hospital scenario, ten partner hospitals each train their own model (teacher) on locally held, labeled radiology images. These teachers then label the unlabeled images at our hospital, and the label with the most votes is selected. Since this majority label could still reveal private patient information, Gaussian noise is added to the vote counts to achieve differential privacy. (Slides 22–24)

The amount of noise required depends on the level of agreement among the teachers. The PATE framework checks this agreement: when the gap between the top two vote counts is large, removing any single patient's data wouldn't change the outcome, so only a small amount of noise is needed (low ε cost). When the gap is small, more noise is required (higher ε cost). To reduce total noise within a limited privacy budget, one should therefore prioritize labeling only those images where teacher consensus is strong, and skip or be cautious with images where agreement is low. (Slides 25–26)
