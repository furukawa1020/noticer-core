# K7 canonical synthetic comparison fixture

The fixture declares one public action/deadline/service contract, one public
fault trace, one observer field set, fixed cost units, and a synthetic scenario
corpus. Private readiness and synthetic signal values remain scenario-local;
they are not part of the public utility digest.

One function derives case, observer, utility, fault, cost, and corpus digests
and checks all six against a comparison manifest. Later adapters must derive
their runtime inputs from this fixture rather than reinterpret the digest of
a mechanism-specific input object.

The corpus digest contains synthetic private values and is only suitable for
declared synthetic smoke fixtures. Do not serialize real biosignals or
private readiness into public artifacts or hash low-entropy real private data
into this format. This contract fixes input identity, not privacy or faithful
reproduction of prior systems.
