# QuotientLimit Held-Out Benchmark Corpus

K9-QL-12 freezes 31 benchmark families across readiness, deadline, observer, fault, action, and longitudinal categories. The split unit is the family identifier; parameter variants are never divided across development and held-out sets.

Eight families are held out. Every held-out family has no handwritten template, no known optimum, at least two observers, at least two services, and a nontrivial public fault. Procedural seeds are fixed before results are observed.

The executable corpus contract enforces at least 24 families, at least 8 held-out families, at least 2 private histories per model, explicit horizon 16, sequence horizon 64, a 4-service gate, at least 4 fault classes, and the N0 through N7 negative-model registry.

Held-out outcomes must not be added to this manifest after evaluation. Any future corpus expansion requires new family identifiers and preserves the existing split.
