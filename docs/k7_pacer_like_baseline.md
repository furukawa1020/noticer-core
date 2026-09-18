# K7 Pacer-like fixed-cadence approximation

This is a local approximation of one principle in
[Pacer (USENIX Security 2022)](https://www.usenix.org/system/files/sec22-mehta.pdf):
a schedule selected independently of private content. It is not Pacer's
hypervisor implementation, proof, flow-control design, congestion handling,
loss recovery, or constant-time network stack.

The approximation sends a fixed-size frame at every configured slot when the
public network-availability trace permits it. A frame is sent even without an
action, so the public timing/size trace does not reveal queue occupancy.
The internal action delivery report is private utility evidence, not an
observer-visible frame field. The same action/deadline and fault inputs are
digest-bound to the K7-13 shared comparison manifest.

The report separates bandwidth, maximum pending state, public fault slots,
latency, and missed deadlines. The implementation does not claim deployment
traffic privacy or equivalence to the original Pacer system.
