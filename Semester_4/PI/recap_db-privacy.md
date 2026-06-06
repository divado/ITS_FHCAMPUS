# Recap Database Privacy

**1. What is k-anonymity in a database?**

K-anonymity means modifying a table so that each record, when looking only at the quasi-identifier (QID) columns, has at least k-1 other identical records. For example, 2-anonymity requires every QID combination to appear at least twice, so no individual can be uniquely identified by their quasi-identifiers alone. (Slides 8 and 13)

**2. What needs to be done to transform a db to a 2-anonymous db?**

Two techniques are used: *generalization* (replacing specific values with broader categories, e.g. exact ZIP codes become ranges like 9413\*, or exact birth dates become year ranges) and *suppression* (removing entire records that are too unique and would otherwise force excessive generalization). (Slides 7, 9, 10, 12)

**3. Why is k-anonymity not sufficient for protecting privacy?**

Two attacks defeat it. The *homogeneity attack* exploits cases where all records in an equivalence class share the same sensitive attribute value — even though the QIDs are k-anonymous, the attacker learns the sensitive value with certainty. The *background knowledge attack* uses external information (e.g. knowing someone's ethnicity and associated health statistics) to narrow down which sensitive value applies, even when the class contains diverse values on paper. (Slides 14, 15, 16, 17)

**4. What are the Local and Global differential privacy mechanisms?**

*Local DP* adds noise to each individual's data before it enters the database, so the database owner never sees the true values — no trust in the owner is required. *Global DP* keeps the raw data in the database and only adds noise to the query results; this requires trusting the database owner but generally achieves better accuracy for the same privacy level. (Slide 30)

**5. What does DP guarantee?**

Differential privacy guarantees that an adversary cannot determine whether any single individual's data was included, changed, or removed from the dataset, regardless of what auxiliary information the adversary possesses. It ensures only population-level statistical information is disclosed, never individual-level data. (Slide 19)

**6. What are parallel or neighbour databases?**

Neighbour (or parallel) databases are copies of the original database in which exactly one row has been removed. For a database with n rows, you create n neighbour databases — one for each possible removed row. They are used to measure how much a query's output changes when a single person's data is absent. (Slides 23, 24)

**7. How do we calculate the sensitivity of a query?**

Sensitivity is the maximum absolute difference between the query result on the original database and the query result on any of its neighbour databases. You run the query on the full database, then on every neighbour database, and take the largest observed difference. For a sum query on binary data, the sensitivity is 1; for a mean query it is much smaller (roughly 1/n). (Slides 25, 26)

**8. What distributions can be used for adding noise to a query?**

The Laplace distribution is the primary noise distribution presented. It is composed of two back-to-back exponential distributions, parameterized by a mean (μ, typically 0) and a scale parameter b (beta). The Gaussian distribution is also shown as a comparison. (Slide 32)

**9. What is epsilon and how is it related to the noise amount?**

Epsilon (ε) is the *privacy loss parameter*. The noise scale is calculated as beta = sensitivity / epsilon. A smaller epsilon means stronger privacy protection but requires adding more noise (less accuracy). A larger epsilon means less noise and better accuracy but weaker privacy. (Slide 31)

**10. What happens if we add too little or too much noise?**

Too little noise fails to protect privacy — an attacker can still infer individual values through differencing attacks. Too much noise destroys the utility of the data, making query results too inaccurate to be useful for research. The challenge is finding the right balance. (Slides 30, 31, 33)

**11. How is the privacy budget used?**

The total privacy budget (ε) is consumed across multiple queries. Each query uses a portion of the budget, and the individual epsilons are summed. For example, with a total budget of ε = 0.5, if the first query uses 0.1 and the second uses 0.2, only 0.2 remains. Once the budget is exhausted, no more queries can be answered without violating the privacy guarantee. (Slide 36)

**12. What are advantages and drawbacks of differential privacy?**

*Advantages:* mathematically provable privacy guarantees; protection against arbitrary risks beyond just re-identification; automatic neutralization of linkage attacks (past, present, and future); applicability to AI training. *Drawbacks:* works best only for low-sensitivity queries; requires a large privacy budget if many queries are expected; handles numeric queries natively but needs data transformation for non-numeric queries (e.g. categorical data requires histogram-type query functions). (Slide 39)
