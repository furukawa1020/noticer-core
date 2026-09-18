# K7 NetShaper-like windowed-noise approximation

The [NetShaper paper](https://www.usenix.org/system/files/usenixsecurity24-sabzi.pdf)
studies tunable differentially private network shaping. This local simulator
only captures a windowed noisy transmission-count tradeoff. It is not the
authors' code, tunnel endpoint, privacy accountant, clipping policy, or proof.
Its Laplace noise scale is a simulator parameter, **not** a DP epsilon.

Each window samples a seeded noisy count from the pending action queue,
bounded by a frame cap. Public network-unavailable slots cannot transmit.
Frames have fixed byte size; their presence and timing remain observable and
may depend on private queue state. Delivery metadata and deadlines remain
private utility evidence. The config, action/deadline trace, and public fault
trace are digest-bound to the K7-13 comparison manifest.

Reports keep bandwidth, pending state, public faults, latency, and deadline
failure separate. No formal DP or AQNI guarantee is claimed for this
approximation.
