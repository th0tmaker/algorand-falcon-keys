# FN-DSA vs Falcon-DET1024: PQ Signing Scheme Comparison for Algorand

> [!WARNING]
> **Disclaimer**
>
> This document is not the work of a credentialed cryptographer, mathematician, or computer
> scientist. It is an exploratory exercise — an attempt to understand a technically complex
> subject through research, reasoning, and iterative refinement. It should not be treated as
> authoritative, peer-reviewed, or free of error.
>
> AI assistance was used throughout: to help compile and structure the document, to reason 
> through technical arguments, identify gaps and inconsistencies, and cross-reference claims
> against primary sources. The underlying analysis reflects the author's own understanding; 
> AI was a tool for feedback and knowledge scaffolding, not a substitute for domain expertise.
>
> Readers with relevant expertise are encouraged to verify claims against the primary sources
> cited and to treat any conclusions as starting points for further investigation, not settled
> facts.

## Table of Contents

- [Context](#context)
  - [Why PQ Migration Is Important](#why-pq-migration-is-important)
- [Shared Foundation](#shared-foundation)
- [Parameter Set: 512 vs 1024](#parameter-set-512-vs-1024)
- [FN-DSA Advantages](#fn-dsa-advantages)
  - [Security](#security)
  - [Signature Format](#signature-format)
  - [Implementation](#implementation)
  - [Protocol and Ecosystem](#protocol-and-ecosystem)
- [Falcon-DET1024 Advantages](#falcon-det1024-advantages)
- [Arguments Examined and Resolved](#arguments-examined-and-resolved)
  - ["Different machines might produce different signatures"](#different-machines-might-produce-different-signatures)
  - ["FN-DSA requires a good source of randomness"](#fn-dsa-requires-a-good-source-of-randomness-which-signers-didnt-need-before)
  - ["The blockchain industry doesn't always follow NIST"](#the-blockchain-industry-doesnt-always-follow-nist)
  - ["We have a tried and trusted implementation in production for years"](#we-have-a-tried-and-trusted-implementation-in-production-for-years)
  - ["FN-DSA's non-determinism is a computation problem"](#fn-dsas-non-determinism-is-a-computation-problem-not-just-an-output-difference)
  - ["Cross-machine floating-point determinism requires FPEMU"](#cross-machine-floating-point-determinism-requires-fpemu)
- [Protocol Migration Implications](#protocol-migration-implications)
  - [Account Address Scheme](#account-address-scheme)
  - [Verification: Stateless vs Stateful Design](#verification-stateless-vs-stateful-design)
  - [Block Structure: Signature Storage](#block-structure-signature-storage)
  - [Archival Storage](#archival-storage)
  - [Multi-Signature Implications](#multi-signature-implications)
  - [Migration Path and Hybrid Period](#migration-path-and-hybrid-period)
  - [Batch Verification Loss](#batch-verification-loss)
- [Post-Quantum VRF](#post-quantum-vrf)
- [The "Do Not Disturb a Sleeping Falcon" Attack](#the-do-not-disturb-a-sleeping-falcon-attack)
- [Key Gaps in Falcon-DET1024](#key-gaps-in-falcon-det1024)
- [Use-Case Differentiated View](#use-case-differentiated-view)
- [Verdict](#verdict)
- [References](#references)

---

> [!NOTE]
>
> **On the word "determinism":** Three related but distinct notions appear in this document.
>
> *Signing determinism* means the same private key and message always produce the same signature
> bytes — FALCON-DET1024's defining property. Achieving it requires two computational preconditions:
>
> - **Deterministic random tape**: the PRF `SHAKE(logn‖privkey‖data)` ensures the same
>   pseudorandom byte stream is generated on every signing call for the same key and message.
> - **Functional equivalence**: the signing algorithm that consumes those bytes must have the same
>   input-output behaviour across different hardware and compiler configurations — this is the
>   floating-point emulation (`FALCON_FPEMU`) concern.
>
> The spec (Section 3.4.2) states explicitly: *"it is not enough to generate a repeatable stream of
> pseudorandom bytes; the actual signing procedures that consume those bytes should ideally be
> functionally equivalent."* A repeatable tape without functional equivalence is insufficient.
>
> The spec also includes a `salt_version_byte` as an escape hatch: when functional equivalence
> breaks — due to a bug fix, optimisation, or platform change — incrementing the version refreshes
> the message-to-syndrome mapping without requiring key replacement.
>
> Unless stated otherwise, "determinism" in this document refers to signing determinism.

## Context

This document compares two post-quantum signature schemes:

- **FALCON-DET1024** — the deterministic Falcon variant specified by Lazar and Peikert (Algorand
  Inc., November 2021) in [`falcon-det.pdf`](https://github.com/algorand/falcon/blob/main/falcon-det.pdf),
  currently used in Algorand's state proofs and exposed as an AVM opcode.

- **FN-DSA** — the forthcoming NIST standard (FIPS 206), based on Falcon with conservative modifications
  that enable a formal security proof.

**The comparison covers security, protocol fit, practical migration implications, and open questions
raised in community discussion.**

Algorand's post-quantum strategy maps onto three phases, each at a different stage of resolution:

**Securing the past — done.** State Proofs using FALCON-DET1024, deployed in the "Renaissance
Block" in 2022, provide a quantum-safe record of Algorand's chain history. This phase is
complete.

**Securing the present — two open questions.** The first MainNet Falcon-authorized transaction
was demonstrated in November 2025, but two architectural questions remain unsettled.

1. How to be crypto-agile when it comes to transaction signing?

- An opcode wrapped in a LogicSig abstraction is the flexible path — scheme-agnostic,
deployable without protocol changes, and useful for observing which PQ schemes developers
actually adopt and how they perform under real AVM constraints. A native protocol-level
account type is the canonical path — full feature parity with Ed25519, no ARC dependency,
familiar patterns for wallets and tooling, and protocol-enforced security guarantees without
relying on ecosystem convention. These two paths are not mutually exclusive: the opcode layer
provides agility and experimentation while the native account type provides the stable
ecosystem-wide standard. Both can coexist, serving different use cases and migration timelines
simultaneously.

2. Which scheme to promote to native status, and when?

- FALCON-DET1024 is the most natural near-term candidate — several years in production,
already an AVM opcode, and a performance profile (low latency, high throughput) that fits
Algorand's design constraints. The theoretical advantages FN-DSA holds over FALCON-DET1024
are either not meaningful in Algorand's specific deployment context or unlikely to be
exploited in practice. That (combined with the significant implementation cost of introducing
FN-DSA from scratch against an already deployed and tested scheme) makes the case for choosing 
FN-DSA over FALCON-DET1024 as the first native PQ account type a difficult one to argue.

**Securing the future — two timelines.** Algorand's Pure Proof-of-Stake consensus selects
block proposers and committee members each round using a Verifiable Random Function. Each
participating node uses its private VRF key to compute a pseudo-random output against the
current block seed; if the output falls within the node's stake-proportional threshold, it
is selected. The node then publishes its VRF proof, which anyone can verify using the
corresponding public key — confirming the selection was legitimate without revealing the
private key. This combination of a secret key for generation and a public proof for
verification is what makes VRFs suitable for trustless consensus. Replacing the current
ECVRF-based implementation with a post-quantum construction is the hardest open problem in
Algorand's PQ roadmap: existing lattice-based schemes, including Falcon variants, do not
satisfy all properties a cryptographically valid VRF requires, and the lattice-based
constructions that do meet those criteria, still carry proof sizes and scalability gaps
that make them impractical today. The near-term path may include a hash-based PQ VRF —
easier to implement, smaller proofs, compatible with existing AVM hash opcodes, and grounded
in the same collision resistance assumptions already present throughout the protocol.
The long-term path, if lattice-based constructions mature sufficiently (estimated 10+ years),
is a lattice-based Ring VRF — one that provides committee anonymity as an additional
security property. Publishing a VRF proof reveals which validator was selected; Algorand's
design substantially mitigates the resulting exposure because cryptographic self-selection
means revelation and action are simultaneous — by the time an adversary learns who was chosen,
the participant has already broadcast their vote, and sub-3-second finality leaves no practical
window for targeted interference. Ring VRFs go further by removing the exposure entirely,
decoupling proof validity from identity.

### Why PQ Migration Is Important

At a high level, Algorand accounts are controlled in two ways: by a **secret** (a private key
whose holder signs transactions — Standard single signature and MultiSig) or by a **program**
(code logic that approves or initiates transactions — LogicSig and Applications). The PQ migration
challenge splits along this line: secret-controlled accounts must migrate away from quantum-vulnerable
signature schemes; program-controlled accounts must ensure their logic cannot be bypassed or exploited
through some unintended path. Both are live concerns — they require different solutions.

Several distinct forces motivate post-quantum migration:

**1. Store Now, Decrypt Later (SNDL)** — Adversaries are already recording block data and
mempool traffic. Any Ed25519 public key visible on-chain today is a future target: once a CRQC
(Cryptographically Relevant Quantum Computer) exists, historical public keys can be used to
extract private keys, enabling forgeries from accounts that appeared safe at registration time.
For Algorand specifically, this threat is stronger than the standard SNDL framing: a single-signature
account address directly encodes the Ed25519 public key without an additional hash layer — unlike
Bitcoin or Ethereum where the public key remains hidden until the account's first spend.
A CRQC can target any known Algorand address with no prior transaction history required.

**2. Real-time mempool attacks** — If a CRQC were fast enough to break ECC within the mempool
confirmation window, it could extract the sender's private key from a broadcast transaction and
front-run it before finalisation. This is the most speculative concern — it requires a very
capable, fast CRQC — but represents a genuine tail risk.

**3. Avoiding emergency migration chaos** — Reactive migration under threat leads to rushed
code, contested hard forks, and community splits. Two failure modes are worth naming: doing
nothing until a credible quantum threat appears risks a panic migration, where users rush to
rekey simultaneously, compete for block space, and make operational mistakes under pressure;
forcing a global migration too aggressively risks users losing access to accounts, funds,
applications, or governance roles — harm potentially comparable to the attack the migration
is meant to prevent. A proactive, gradual, opt-in migration preserves the years needed for
careful design, audit, and orderly ecosystem transition.

**4. Regulatory and institutional compliance** — NIST finalised FIPS 203/204/205 in August 2024.
CISA and ENISA are mandating PQC migration timelines. Chains that lag will face compliance
barriers with regulated institutional counterparties.

**5. Program-controlled account bypass (Algorand-specific)** — Roughly half of all 32-byte
Algorand addresses are mathematically valid Ed25519 public keys. For program-controlled accounts
(LogicSig, Application, Multisig), a CRQC could derive the matching private key for such an
address and bypass program logic entirely — even though no Ed25519 key was intentionally
generated. This is not specific to the choice between FN-DSA and FALCON-DET1024; it affects
any Falcon-based deployment on Algorand and requires per-account-type mitigations.

**6. Grover's algorithm and hash security** — Grover's algorithm quadratically speeds up
second-preimage search against hash-derived addresses (Multisig, LSig, Application). For
Algorand's 32-byte SHA-512/256 output with domain separation, the security margin remains very
large — this informs the address derivation design for native PQ accounts but does not drive
the same urgency as Shor's on Ed25519.

The timeline for CRQCs remains uncertain — most estimates place 10–20 years — but the practical
guidance is: start migration engineering now, so the protocol is ready before the threat
materialises. Note on consensus: Algorand's ephemeral participation key scheme already limits
the quantum threat to consensus to real-time forgery within an active round — a narrow window
given the 80% honest-stake safety guarantee. The primary exposure is at the account layer
(spending keys), not the consensus layer.

---

## Shared Foundation

Both schemes are built on identical mathematical primitives:

| Property | Falcon-DET1024 | FN-DSA/1024 |
|---|---|---|
| Ring degree | n = 1024 | n = 1024 |
| Modulus | q = 12289 | q = 12289 |
| Sampler | FFO (Fast Fourier Orthogonalization) | FFO (same) |
| Key generation | NTRU trapdoor generation | NTRU trapdoor generation (same) |
| Underlying hardness | t-R-ISIS (~279-bit core-SVP) | t-R-ISIS (~279-bit core-SVP) |
| Private key size | 2305 bytes | 2305 bytes |
| Public key size | 1793 bytes | 1793 bytes |

The Paper 2024/1769's lattice estimator (Figure 11) gives raw ISIS hardness as 2^121.2 for
n=512 and 2^279.2 for n=1024. The paper's summary table rounds these to 120 and 278; both
representations appear throughout this document. The ~279-bit hardness for n=1024 provides a
23-bit buffer above the 256-bit target.

---

## Parameter Set: 512 vs 1024

A natural question is whether Falcon-512 or FN-DSA/512 could be used to reduce key and signature
sizes. The Paper 2024/1769 gives concrete provable security numbers:

| Variant | ISIS hardness (pre-proof) | Qs=2^64 security (post-Rényi) | Qs=2^58 security (post-Rényi) |
|---|---|---|---|
| Falcon+/512 | ~121 bits (2^121.2) | 113 bits | 119 bits |
| Falcon+/1024 | ~279 bits (2^279.2) | 256 bits | 256 bits |

The ISIS hardness column is the raw pre-proof baseline — the hardness of the underlying lattice
problem before any reduction losses are applied. The provable security columns are after all
reduction losses including the Rényi divergence terms. For Falcon+/512 the Rényi loss accounts
for nearly all of the gap (~8 bits at Qs=2^64, ~2 bits at Qs=2^58); query overhead is negligible
at this parameter level. For Falcon+/1024 the total 23-bit gap (279→256 at Qs=2^64) breaks down
as ~8 bits Rényi loss and ~15 bits random oracle query overhead.

Falcon-512's ISIS hardness sits at ~121 bits — close to the NIST Level I target with little margin.
The 113/119-bit provable security figures at Qs=2^64/2^58 are **proof tightness** results, not
concrete exploitable attacks: no known lattice attack on Falcon-512 improves with more observed
signatures. The Rényi divergence loss is an artifact of the security reduction, not an adversarial
capability.

The real concern for long-lived Falcon-512 keys is different: the thin ISIS baseline leaves almost
no room for future algorithmic improvements. Lattice cryptanalysis has historically advanced, and a
7-bit improvement would push Falcon-512 below the security target. Falcon-1024's ~279-bit baseline
provides a 23-bit buffer above its 256-bit target — a substantially more comfortable cushion against
future progress.

**The ephemeral key argument does not hold for Algorand's state proofs.** Algorand's state
proof scheme uses a two-level structure: each participant pre-generates a Merkle tree of
one-time Falcon keys; each signing event consumes one leaf, then the private key is deleted.
The private keys are genuinely ephemeral. However, two factors make Falcon-512 insufficient
regardless.

First — and sufficient on its own — state proofs **are** Algorand's post-quantum security
solution. Their entire purpose is to make historical blockchain attestations
quantum-resistant. Using Falcon-512 would defeat that purpose independently of any key
visibility concern. The implementation makes the security target explicit:
`STRENGTH_TARGET = 256`, with the comment *"256 = k + 2q where (k=128, q=64) accounts for
a quantum attacker's Grover-style speedup over hash-based components"* — the system is
designed around 128-bit post-quantum security throughout. Applying quantum sieving to the
lattice layer (which provides roughly quadratic speedup — the same factor-of-2 reduction as
Grover's algorithm on symmetric cryptography):
- Falcon-512: ~121-bit classical ISIS → **~60-bit post-quantum** — below the 128-bit target
- Falcon-1024: ~279-bit classical ISIS → **~140-bit post-quantum** — comfortably above it

Falcon-512 in a system whose purpose is quantum resistance would leave the signature layer
as the weakest link at 60 bits — half the security the system is designed to provide.
Falcon-1024 is the only internally consistent choice, which is precisely what the
`falcon-det.pdf` specification reflects in targeting "NIST post-quantum security category 5
(the highest defined level)."

Second — reinforcing the above — the ephemeral public keys of actual signers are permanently
visible on-chain. Block headers store only a Merkle root (a commitment over all of a
participant's pre-generated keys, not the individual keys themselves), so unused keys remain
hidden. But each State Proof transaction opens a pseudorandomly selected subset of signer positions
— chosen via a SHAKE-256 coin toss — and each opened position includes the full Merkle
authentication path and the individual ephemeral public key of that signer, embedded
directly in the fixed-size representation of each revealed Merkle signature. Once a key has been used in a State Proof it is permanently
visible in the transaction record. A quantum adversary can derive the corresponding private
keys long after deletion and forge state proofs for past epochs retroactively — manipulating
what light clients believe about historical chain state. This threat is independent of the
first argument; the 60-bit security floor rules out Falcon-512 even before key visibility
enters the picture.

---

## FN-DSA Advantages

### Security

- **Formal security proof** — FN-DSA is proven secure in the random oracle model (Paper 2024/1769).
  The proof establishes that breaking FN-DSA is *equivalent* to solving t-R-ISIS — necessary and
  sufficient. Any improvement in lattice cryptanalysis directly translates to an attack on FN-DSA,
  and vice versa. FALCON-DET1024 has no formal security proof.

  To be precise: FALCON-DET1024 retains the **GPV structure** — NTRU lattice trapdoor,
  hash-to-point, FFO sampler, short vector output — but not **GPV randomized sampling**. The
  GPV security proof works by arguing that fresh Gaussian noise makes each signature
  statistically independent of the secret key. Once that fresh randomness is replaced by a
  deterministic function of the key and message (`SHAKE256(sk || msg)`), that statistical
  independence argument breaks — the distribution is no longer provably independent of the
  secret key, it only behaves as if it is. The scheme is structurally GPV; the proof is not.

  This gap was a **known and deliberate tradeoff**: Peikert — co-author of the GPV framework
  itself — co-authored `falcon-det.pdf` and scoped the scheme explicitly to SNARK-friendly compact
  certificates. The Falcon spec (Section 2.2.2) acknowledged de-randomization as legitimate for
  targeted applications: *"While this solution can be applied in a few specific use cases, we do
  not consider it for Falcon."* Paper 2024/1769 later formalised the gap and proved the randomised
  variant secure — a proof that did not exist when the deterministic spec was written in 2021.

  A critical contribution of the paper is Rényi order optimisation. The security reduction works by
  *programming* the random oracle: for each signing query it picks a fresh salt *r*, chooses a
  syndrome it can solve, and programs `H(pk, r, m) = c` in its simulation — requiring fresh,
  independent *r* per query. Rényi divergence of order *a* then bounds how close this programmed
  distribution is to the real one across all queries. The Falcon NIST spec used *a* = 2^λ,
  producing a **60-bit loss** (279 → ~219 bits); Paper 2024/1769's optimised *a* cuts this to
  **8 bits**. With the remaining ~15-bit random oracle query overhead: 279 − 8 − 15 ≈ **256 bits**
  provable security. FALCON-DET1024 cannot claim these numbers — without a random salt the
  reduction never starts and the Rényi argument has nothing to bound.

  | Variant | Oracle programmable? | Distribution clean? | Outcome |
  |---|---|---|---|
  | FALCON-DET1024 | No — fixed salt | — | No reduction exists |
  | Standard Falcon | Yes — random *r* before loop | No — fixed *c* skews *s* | Proof fails |
  | Falcon+ / FN-DSA | Yes — fresh *r* per iteration | Yes | 8-bit loss, 256-bit security |

  FALCON-DET1024 shares the same ~279-bit ISIS baseline as Falcon+/1024 — no known attack comes
  close and cryptanalysts attack both equally. But without a proof reduction the baseline is a
  plausibility argument, not a theorem: there is no formal guarantee that forging a signature
  requires solving ISIS. Structural attacks that bypass ISIS hardness entirely cannot be ruled out.
  The Do Not Disturb attack is exactly this — it ignores the ~279-bit hardness completely and
  exploits a floating-point property unique to deterministic signing.

- **Public key binding and BUFF security** — FN-DSA incorporates a hash of the public key into
  every signature: `H(hpk, r, m)` instead of `H(r, m)`. Without binding, multi-user security
  degrades by approximately log₂(N) bits where N is the number of accounts — roughly 20 bits for
  Algorand's scale. With binding, each account's security is evaluated independently at full
  strength. This is the Pornin-Stern transformation [PS05], known since 2005. pk binding is also
  the mechanism that delivers BUFF security (Beyond UnForgeability Features), formalised in Paper
  2020/1525 and shown to follow from pk binding for FALCON by Paper 2024/710 (Düzlü, Fiedler,
  Fischlin). The three resulting properties are:
  - *Exclusive ownership (M-S-UEO)*: a valid signature cannot verify under two distinct public keys —
    a signature is cryptographically bound to the key it was produced under
  - *Message-bound signatures (MBS)*: a valid signature cannot verify two different messages under
    the same public key
  - *Non-resignability (NR)*: given a signature on an unknown message, an adversary cannot produce
    a valid signature for the same message that verifies under a different key pair

  Standard Falcon (without pk binding) achieves only MBS — it fails EO and NR (per Paper 2024/710,
  Table 1). FN-DSA gains all three via pk binding, without increasing signature size. These
  properties are directly relevant to blockchain accountability: EO ensures a signature cannot be
  claimed by a different key, and NR prevents a party from repurposing an observed signature under
  their own key.

  FALCON-DET1024 shares the same BUFF gap as standard Falcon. Its hash is `H(fixed_salt, m)` —
  no public key, no random salt — so it achieves MBS but fails EO and NR for the same reason.
  This is not an additional weakness introduced by determinism; it is the same gap present in
  standard Falcon. The deterministic property and the BUFF gap are orthogonal: fixing one does
  not affect the other.

  In Algorand's current design the EO gap is partially mitigated by the address scheme. With
  Ed25519, the 32-byte public key IS the address — "only key X could produce this signature"
  holds both mathematically (Ed25519 has native EO) and at the protocol level. A PQ scheme
  migration would hash the 1793-byte public key to derive a 32-byte address
  `H("PqAddr" || pubkey_bytes)`, and verification uses the key registered for that
  address — so the address-to-key binding still enforces which key is checked.

  The meaningful difference is what happens *outside* that infrastructure. FN-DSA's
  `H(r, pk, m)` makes the signature mathematically inseparable from the specific key — a
  verifier handed only `(pk, m, σ)` can be certain no other key could have produced it.
  FALCON-DET1024's `H(fixed_salt, m)` provides no such mathematical guarantee; attribution
  relies entirely on the surrounding system having correctly associated the key with the address.
  This matters in SNARK circuits, cross-chain proofs, or any context where the Algorand address
  infrastructure is not present to enforce the binding.

### Signature Format

- **Smaller fixed-size signatures** — FN-DSA/1024 produces exactly 1280-byte signatures. The padded
  format works reliably because rejections due to oversized compressed signatures can trigger a
  fresh nonce, allowing a retry — something FALCON-DET1024 cannot do, leaving it with
  variable-length compressed signatures (up to 1423 bytes max). FALCON-DET1024 signatures can
  be transcoded to constant-time (CT) format, which is fixed-size, but at 1538 bytes — larger
  than FN-DSA's 1280 bytes. Fixed size simplifies everything downstream: buffer allocation,
  network framing, storage calculations, and block capacity planning all become deterministic.

### Implementation

- **Pure Rust implementation by Pornin** — Pornin's `rust-fn-dsa` (cited as `[Por25a, Por25b]`
  in the Paper 2024/1769) provides a pure Rust implementation with no C FFI, no libc
  linkage, and full Rust memory safety. FALCON-DET1024's reference implementation is C-only,
  requiring a C toolchain and carrying an unsafe FFI boundary in any Rust integration.

  Note: `rust-fn-dsa` is pre-1.0 and explicitly pre-standard — the README warns that it does
  not yet implement the "real" FN-DSA (FIPS 206 is not yet finalised), and backward
  compatibility will not be maintained until version 1.0. It is high-quality implementation work
  by a trusted author but should not be treated as a stable production library until the standard
  lands and the library tracks it.

- **Floating-point handling** — FALCON-DET1024's C library mandates `FALCON_FPEMU=1` (blanket
  integer emulation of all floating-point) to guarantee cross-machine consistency, at a measured
  ~15x signing slowdown (verification is unaffected — it uses no floating-point). FN-DSA
  implementations can use native `f64` on 64-bit platforms where strict IEEE-754 is guaranteed
  (x86_64, aarch64), falling back to software emulation only on 32-bit hardware — avoiding the
  blanket signing speed penalty without sacrificing correctness.

- **RISC-V support and deployment flexibility** — `rust-fn-dsa` explicitly supports RISC-V
  (RV64GC with D-extension) and its modular crate structure (`fn-dsa-vrfy` etc.) allows
  verification-only deployments for light-client use cases. For zkVM environments (SP1, RISC0),
  the picture is less clear: `rust-fn-dsa` has no `no_std` support, which most zkVM guest
  environments require. FALCON-DET1024's C code can in principle be compiled to RISC-V and
  linked via FFI in some zkVM environments (SP1 can link C), but C code requires libc and
  syscall support that constrained environments may not provide. For both schemes, the
  practically relevant zkVM operation is **verification** — which is integer-only arithmetic
  in both cases and equally feasible regardless of implementation language. Neither library
  makes a credible production zkVM claim today.

### Protocol and Ecosystem

- **ABFT spec explicitly permits non-determinism** — The Algorand ABFT specification
  (Section 3, release 7791a63) states verbatim:

  > *"The signing procedure is allowed to produce a nondeterministic output, but the functions
  > above must be well-defined with respect to a given input to the signing procedure (e.g., a
  > procedure that implements Verify(Sign(...)) always returns the same value)."*

  The spec formally defines three functions on `y = Sign(...)`:
  1. **Validity** — `Verify(y, ...) ≠ 0` iff `y` was produced by `sk` (cryptographic correctness)
  2. **Total ordering** — a total order exists on possible outputs `y` (for sortition/committee selection)
  3. **Randomness extraction** — `Rand(y, pk)` yields a well-defined pseudorandom 256-bit value (for VRF-based leader selection)

  The nondeterminism clause then adds that these three functions must remain well-defined even
  if the signing output is nondeterministic — using `Verify(Sign(...))` always returning the same
  value as the illustrative example of what "well-defined" means.

  Determinism — producing the same bytes every time — appears nowhere in the three formal
  requirements. FN-DSA satisfies all three.

  This distinction matters for scope: determinism is not a requirement for a protocol-native
  signing scheme, and FN-DSA's non-determinism is not an obstacle to native adoption. Where
  determinism becomes a hard requirement is in the construction of a cryptographically valid
  VRF for sortition — the same `(sk, input)` must always produce the same output to prevent
  validators from running the algorithm multiple times to obtain a favourable committee weight.
  That requirement belongs to the VRF layer, not to the general-purpose signing scheme.

  **Node congruency** does not change this. All nodes agree on ledger state by receiving and
  verifying the *same broadcast signature bytes* — no node independently recomputes what a
  signature should be. Equivocation detection (Section 10 of the ABFT spec) is defined as two
  votes with *different proposal values* (`v1 ≠ v2`), not different signature bytes for the same
  vote. A non-deterministic scheme producing different bytes for the same `(I, r, p, s, v)` is
  not an equivocation in the spec's definition.

- **NIST FIPS standardisation** — FN-DSA is the forthcoming NIST standard. Hardware security
  modules, TPMs, and secure enclaves will eventually support it natively, and general-purpose
  language ecosystems will ship implementations targeting the standard. The deterministic variant
  is unlikely to receive this kind of broad infrastructure support, though blockchain-specific
  tooling and libraries may continue to support it given its established use in state proof
  and SNARK applications.

  Early ecosystem adoption of FN-DSA is uneven — standardisation is a long-term advantage, not
  an immediate given. Bitcoin's BIP360 proposal (the leading PQ signature opcode effort for
  Bitcoin, 2026) explicitly excludes FN-DSA for now, with the lead developer citing implementation
  complexity of the discrete Gaussian sampler. This is a concrete example of a major ecosystem
  making a near-term adoption decision against FN-DSA despite its NIST track. The argument holds
  over a multi-year horizon but should not be read as implying frictionless near-term uptake.

- **Ecosystem interoperability** — Wallets, exchanges, and SDKs can use any standard FN-DSA
  library. Variant-specific tooling is not required. Using a non-standard variant forces every
  external developer to understand and implement an Algorand-specific deviation, compounding the
  integration burden across the ecosystem.

- **Domain separation context strings** — FN-DSA includes a context string input as part of
  the cryptographic primitive itself, confirmed by the IETF CMS draft (draft-turner-lamps-cms-fn-dsa-00):
  *"FN-DSA has a context string input that can be used to ensure that different signatures are
  generated for different application contexts."* The maximum size is **255 bytes**, confirmed
  directly in FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) — both encode the context as
  `len(ctx) || ctx` with a 1-byte length prefix, enforcing a 255-byte maximum and returning an
  error if exceeded. NIST applied this consistently across all three PQC signature standards.

  This is a FIPS 206 standardisation addition — neither the original Falcon specification (v1.2)
  nor FALCON-DET1024 include a context string mechanism. Both hash only the salt and message:
  `H(r || m)` and `H(fixed_salt || m)` respectively. Any domain separation for FALCON-DET1024
  must be implemented at the application layer by the caller, which is ad hoc, not standardised,
  and easy to omit. FN-DSA builds it into the primitive, enabling explicit separation between
  transactions, state proofs, and consensus votes using the same key without collision risk.

- **Why ECDSA must be deterministic but FN-DSA does not** — Pornin is best known for
  authoring RFC 6979 (2013), which made ECDSA deterministic — the standard adopted by Bitcoin,
  Ethereum, and virtually every modern ECDSA implementation. That work was a security necessity,
  not a philosophical preference. In ECDSA, the signature is `s = k⁻¹(hash(m) + r·d) mod n`
  where `k` is a random nonce and `d` is the private key. Reusing `k` for two different messages
  gives two equations with the same unknowns — solving for `d` is trivial linear algebra. This
  is exactly what compromised the PlayStation 3 (2010, static `k`) and Android Bitcoin wallets
  (2013, weak PRNG producing repeated `k` values). RFC 6979 eliminated the failure mode
  structurally by deriving `k` deterministically from the private key and message.

  FN-DSA has no equivalent failure mode. The random salt `r` is a hash input, not a nonce in
  an algebraic equation alongside the private key. Reusing `r` across different messages produces
  different hash targets and yields no recoverable linear system. Randomness in FN-DSA serves the
  security proof — it is what makes the GPV reduction work — rather than patching a catastrophic
  reuse vulnerability. The scheme is non-deterministic because the underlying mathematics require
  it for provable security, not because determinism was overlooked.

---

## Falcon-DET1024 Advantages

- **Already deployed** — FALCON-DET1024 has been in production in Algorand's state proof
  infrastructure since 2022 and is exposed as an AVM opcode. In November 2025, Algorand
  demonstrated the first MainNet transaction authorized with Falcon signatures via account
  abstraction — the first concrete step toward securing ledger accounts. Migration
  of the full protocol stack would require substantial testing and validation effort.

- **Determinism as a systemic property** — Determinism means the same input always produces
  the exact same output. Beyond cryptography, this property underpins reliability across digital
  systems: it enables static test vectors (if output matches the expected string, the code is
  correct), reproducible builds (compiling twice yields the identical binary, proving no hidden
  modification), idempotent APIs (retrying a call cannot produce a different result), and
  cacheable computations (outputs can be stored and reused safely). In blockchain specifically,
  determinism is load-bearing for consensus execution (all nodes must reach the same result
  independently), ZK proof generation (fixed mathematical paths are required to prove a
  statement without revealing data), and fraud proofs (replaying a transaction later must
  produce the same outcome to prove a validator lied). FALCON-DET1024 inherits all of these
  properties. FN-DSA, being randomised, does not — each call may produce different bytes, which
  is mathematically sound but breaks any assumption of byte-identity across invocations.
  The ABFT spec does not require byte-identity, but external tooling, test suites, and
  audit trails built against Algorand may rely on it in practice.

- **Use cases where signing determinism is genuinely required** — There are cryptographic
  constructions where deterministic signing is not a preference but a hard requirement, and FN-DSA
  cannot substitute:

  - *Identity-Based Encryption (IBE)*: In a Falcon-based IBE scheme, key extraction (deriving a
    user's secret key from their identity) is mathematically equivalent to signing. The extracted
    key must be identical every time for the same identity — if you request your key twice, you
    must receive the same bytes, or the scheme breaks. FN-DSA's random nonce would produce a
    different "key" on each extraction, making Falcon-based IBE impossible. The Falcon
    specification itself notes this directly (Section 2.2.1): *"Falcon can be turned into an
    identity-based encryption scheme... However, this requires de-randomizing the signature
    procedure."* Paper 2024/1709 explicitly mentions the Latte HIBE construction as a concrete
    instantiation, under consideration for UK NCSC and ETSI standardisation.

  - *ZK proof aggregation*: Determinism provides a substantial circuit cost saving in any ZK
    aggregation system. Two constraints make per-instance circuit cost high when verifying
    Falcon inside a proof. First, a modulus mismatch: Falcon operates over `q = 12289` while
    proof systems like LaBRADOR require a much larger modulus, so the circuit must treat the
    Falcon relation as an integer equation `s1 + h·s2 = c + k·q`, introducing `k` as an
    additional private witness and adding range checks for every signature. Second, hash cost:
    FN-DSA uses SHA-3/Keccak, which is built on bitwise operations that are expensive to
    express in modular-arithmetic ZK circuits — a single SHA-3 evaluation can require tens of
    thousands of constraints. The witness composition makes this concrete: with randomized
    FN-DSA the prover must supply `w = (s1, s2, r)` — the signature vectors and the random
    salt — as a combined private witness, and the circuit must evaluate `H(r, m)` internally
    to derive the syndrome and verify the linear relation. With FN-DSA's pk-binding variant
    (`H(pk, r, m)`), `pk` is an additional hash input, making the in-circuit cost slightly
    higher still. With FALCON-DET1024 the witness shrinks to `w = (s1, s2)` — the salt is a
    fixed public constant, so the syndrome `H(fixed_salt, m)` is computed outside the circuit
    on a normal CPU and fed in as a known value. The circuit never evaluates SHA-3 at all.
    This is not a marginal saving; it eliminates the dominant per-instance constraint cost
    entirely, reducing proving time by an order of magnitude for large batches. LaBRADOR
    (*Aggregating Falcon Signatures with LaBRADOR*, CRYPTO 2024, IACR ePrint 2024/311) can
    aggregate randomized FN-DSA signatures — accepting `w = (s1, s2, r)` and evaluating the
    hash internally — but the in-circuit SHA-3 cost makes large-batch proving significantly
    heavier. Between the two quantum-safe proof families, LaBRADOR has a structural algebraic
    advantage over STARKs for Falcon statements: both LaBRADOR and Falcon operate in the
    module lattice domain, so LaBRADOR's constraint system handles lattice polynomial
    arithmetic more natively than a STARK, which must emulate the same operations inside a
    polynomial constraint system over a different field. Both still face the modulus mismatch
    between Falcon's q=12289 and the proof system's larger working modulus — this is not
    eliminated by LaBRADOR, only reduced relative to a STARK. The tradeoff runs the other direction on proof size:
    STARK proofs can reach hundreds of KB to several MB depending on statement complexity.
    LaBRADOR's ~74 KB for 10,000 signatures is significantly more compact despite its slower
    proving time. In both cases FALCON-DET1024's determinism provides the same circuit
    advantage: the syndrome is public, SHA-3 never enters the circuit, and the prover works
    only against the polynomial math and range checks.

  - *Post-quantum VRF construction*: A VRF requires that the same (secret_key, input) always
    produces the same output — the uniqueness property. FN-DSA's random nonce directly violates
    this; FALCON-DET1024's determinism satisfies it. However, satisfying uniqueness alone is not
    sufficient: the formal GPV pseudorandomness proof also breaks down under deterministic signing.
    The result is the same split that characterises the entire document. See the dedicated
    [Post-Quantum VRF](#post-quantum-vrf) section for full analysis.

- **SNARK friendliness for [compact certificates](https://ia.cr/2020/1568) — the primary stated motivation** — "SNARK-friendly"
  is a circuit-agnostic descriptor: it means a construction maps to arithmetic circuits with low
  constraint count — algebraic operations, no data-dependent branching, no expensive bitwise
  emulation. It says nothing about which proof system sits behind the circuit. A SNARK-friendly
  construction reduces circuit complexity for pairing-based SNARKs (Groth16, PLONK), STARKs,
  and lattice-based arguments of knowledge (LaBRADOR) — the last two are fully quantum-safe.
  The magnitude of the benefit varies: LaBRADOR benefits most, because both LaBRADOR and
  Falcon share the same lattice algebraic structure, giving LaBRADOR inherent compatibility
  with lattice operations that STARKs must emulate through field translation. Making
  FALCON-DET1024 SNARK-friendly therefore optimises it for quantum-safe proof systems, not
  for quantum-vulnerable ones. With that framing established, the `falcon-det.pdf` spec is
  explicit that SNARK-friendliness is the core reason for choosing derandomization over
  randomized hashing. With a random salt, the digest syndrome depends on the salt in the signature.
  For compact certificates where many signers sign the same message, the SNARK must embed
  computations of *all* digest syndromes — one per signer, all different due to different salts.
  The spec calls this "prohibitive" for SNARK provers. With derandomization, the digest syndrome
  depends only on the message. All signers compute the same digest, the hash can be done once
  outside the SNARK, and the SNARK only needs to prove each signature is valid relative to that
  single pre-computed digest. The spec also notes that CT format is explicitly chosen for SNARK
  circuits because each coefficient has a fixed number of bits (linear functions, cheap constraints),
  while compressed and padded formats are "SNARK-unfriendly" due to data-dependent conditionals.

  Note: FN-DSA's randomized hashing could be partially adapted for compact certificates by passing
  the salts "in the clear" to the SNARK verifier. The verifier computes each digest
  `cᵢ = H(pkᵢ, rᵢ, m)` outside the circuit using the known message, the signer's public key, and
  the provided salt; the SNARK then only proves the short-preimage property. The `falcon-det.pdf`
  spec rules this out as "not succinct in the multiple-signature context, because all the various
  salts would need to be known by the verifier." The practical costs of this approach are
  substantial and compound:

  - **Transmission**: K × 40 bytes of salt data per certificate. For Algorand's state proofs
    where K can be in the hundreds, this adds 10–40 KB per certificate, directly undermining the
    compactness objective.
  - **Verifier work scales with K**: With FALCON-DET1024, the verifier computes one syndrome
    `H(fixed_salt, m)` shared across all signers. With FN-DSA salts in the clear, the verifier
    must compute K independent SHAKE256 evaluations — a K× increase in hash work for every
    entity verifying the certificate, including light clients.
  - **SNARK circuit**: Even with syndromes computed outside the circuit, the circuit still
    contains K independent lattice equation checks and norm bound verifications. With
    FALCON-DET1024 all K instances share the same syndrome, enabling simpler parameterisation.
    With K different syndromes each check is independently parameterised — the circuit does not
    shrink, it only moves the hashing outside.
  - **Succinct property degraded**: K salts plus K public key hashes become required public
    inputs before verification can begin, partially undoing the succinctness that compact
    certificates exist to provide.

  The approach is not an absolute impossibility for small K, but the costs grow with K and
  Algorand's security guarantees constrain how small K can be. The spec's ruling is a
  substantive engineering judgement, not merely a theoretical concern.

  **The two-condition requirement for SNARK-efficient compact certificates:**

  Achieving a single shared digest across all signers — the property that allows hashing to be
  lifted outside the SNARK entirely — requires *both* of the following conditions to hold
  simultaneously:

  1. **No random per-signature salt** — with a random `r`, the syndrome `H(r, m)` differs per
     signing call — each signer draws a fresh `r`, so every signature over the same message
     produces a different syndrome. In the compact certificate context where each validator signs
     once, this means one distinct syndrome per signer. The SNARK must embed N independent hash
     computations. Derandomization (fixed versioned salt) eliminates this: all signers compute
     the same `H(fixed_salt, m)`.

  2. **No public key in the hash** — with pk binding (Falcon+), the syndrome `H(pk, r, m)` differs
     per signer because each signer has a different public key. Even with a fixed salt, the SNARK
     must still embed N hash computations — one per distinct public key.

  Each condition alone is insufficient. Removing the random salt but adding pk binding (as Falcon+
  does) destroys the shared-digest property just as much as randomized salts do. Conversely,
  removing the public key from the hash but keeping a random salt still leaves each signer with a
  different syndrome. FALCON-DET1024 achieves both: no random salt and no pk binding — which is
  what makes it uniquely suited to this specific SNARK application.

  **Beyond State Proofs: ZK proof aggregation for transaction signing**

  The same deterministic property extends to general transaction signing if ZK proof
  aggregation is adopted at the protocol layer. In this context, a block producer would
  verify all transaction signatures and generate a single compact proof attesting their
  collective validity — validators then verify one proof instead of N individual signatures,
  reducing verification overhead to near-zero regardless of block size.

  Each transaction carries a different message, so the shared-digest property that makes
  State Proofs particularly efficient does not apply here — there is no single syndrome
  shared across all transactions. But the per-instance circuit savings remain in full: each
  signature's syndrome is still a public constant computable from the message alone, SHA-3
  still never enters the circuit, and the prover still works only against the lattice
  arithmetic and range checks. The savings are per-instance rather than globally shared, but
  they compound across every signature in the batch. The detailed circuit analysis is covered
  in the ZK aggregation use case above.

  **Choosing the right proof system.** Not all proof systems are equivalent for this purpose.
  Many widely deployed proof systems today — Groth16 and PLONK with KZG polynomial
  commitments — rely on elliptic curve pairings. These are fast and produce tiny proofs, but
  they depend on discrete logarithm hardness over elliptic curves, which Shor's algorithm
  breaks. The failure mode is precise and counter-intuitive: a CRQC cannot break the
  underlying Falcon signatures themselves, but it can forge the elliptic curve pairing
  elements of the KZG commitment. This means an attacker could fabricate an entirely false
  aggregate proof that passes verification — attesting to a transaction history that never
  happened. The individual signatures remain cryptographically sound; the proof wrapping
  them is forged. Deploying quantum-safe signatures inside a quantum-vulnerable proof system
  therefore provides no end-to-end quantum security, regardless of how strong the signature
  scheme is.

  The quantum-safe alternatives are STARKs — which rely only on hash functions and require
  no trusted setup — and lattice-based arguments of knowledge such as LaBRADOR, which use
  lattice commitments rather than pairings. FALCON-DET1024's circuit cost savings apply
  equally to both: the syndrome remains a public input and SHA-3 remains outside the
  circuit whether the outer proof system is a STARK or a lattice SNARK. This is what
  "SNARK-friendly" means in a post-quantum context — the circuit efficiency advantage
  carries through to the proof systems that actually matter for quantum security.

---

## Arguments Examined and Resolved

### "Different machines might produce different signatures"

This is not a protocol problem. Nodes verify what they *receive*; they do not independently
compute what the signature *should* be. If a user's wallet produces signature C on one machine,
that signature is broadcast, verified, and included in the block. The fact that signing the same
transaction on a different machine would produce D or E is irrelevant — C is the only signature
that ever exists in the protocol. Agreement is on validity, not on byte identity.

### "FN-DSA requires a good source of randomness, which signers didn't need before"

Valid as an operational concern but overstated as a security argument. The catastrophic failure
mode of poor randomness is specific to ECDSA, where nonce reuse directly exposes the private key
via a simple algebraic relation. In FN-DSA, the nonce `r` picks a hash target — repeating it
for different messages gives different targets and does not directly yield the trapdoor. Poor
randomness in FN-DSA is a security concern, but not the "sign twice = key exposed" failure mode
that made RFC 6979 necessary.

That said, the RNG concern is stronger in the blockchain context than it would be in general
software, and dismissing it entirely is wrong. The PQC community itself raised this concern
explicitly during FN-DSA standardisation — John Mattsson asked on the NIST PQC Forum whether
FN-DSA's randomization would follow "randomized ECDSA that was used in PS3 software signing"
or hedge like ML-DSA, directly naming the blockchain entropy failure scenario. Several
environments common in the blockchain ecosystem either lack reliable OS-level entropy or make
RNG access structurally difficult:

- **Smart contract VMs** (EVM, WASM-based chains like Near, Polkadot, ICP, and Algorand's own
  AVM) — deterministic execution environments with no access to OS entropy by design. RNG
  requires either an oracle, a commit-reveal scheme, or is simply unavailable.
- **Embedded and constrained signing devices** — HSMs and hardware security keys with limited
  entropy sources where generating cryptographic-quality randomness per signing operation is not
  free. The Android OpenSSL PRNG bug (2013) wiped real Bitcoin wallets through exactly this
  class of failure — a specific SecureRandom implementation flaw caused the PRNG to return
  predictable values, producing repeated `k` values in ECDSA signing and directly exposing
  private keys.
- **Cross-device audit and reproducibility** — in a validator network, deterministic signing
  allows independent reproduction of a specific signature for audit or debugging. With randomized
  signing this is impossible; each signing call produces a fresh output even for the same input.

For Algorand's transaction signing specifically, the concern does not manifest. The AVM only
exposes verification opcodes — verification needs no randomness — and transaction signing happens
off-chain on user devices with full OS entropy access. Algorand's own VRF similarly uses
pseudorandom derivation from the private key and a blockchain seed, not OS-level entropy at
signing time. The RNG argument is a legitimate general motivation for the deterministic design
and is a real constraint in the categories above, but it does not constitute a technical
objection to adopting FN-DSA for Algorand transaction signing specifically.

**Hedged signing — NIST's answer to the entropy problem:**

FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) both specify a "hedged" signing mode as the default,
which directly addresses the entropy starvation and VM reset concerns without requiring full
determinism. The nonce is derived as a three-way PRF:

```
nonce = H(secret_key_seed || fresh_random || message_hash)
```

Concretely in ML-DSA (FIPS 204): `rho'' = H(K || rnd || mu, 64)` where `K` is a secret seed
embedded in the private key, `rnd` is 32 bytes from the system RNG, and `mu` is a hash of the
public key and message. FIPS 205 uses the same structure.

NIST's own rationale (FIPS 204, Section 3.4):
> *"The use of fresh randomness during signing helps mitigate side-channel attacks, while the use
> of precomputed randomness protects against the possibility that there may be flaws in the random
> number generator used by the signer at signing time."*

This creates a "no single point of failure" design:
- If the RNG is good → fully randomized, maximum side-channel resistance
- If the RNG fails or produces repeated output → the secret key + message still produce a unique,
  unpredictable nonce, because an attacker who doesn't know `K` cannot predict the output
- If the RNG produces all zeros → the scheme degrades gracefully to deterministic, identical to
  FALCON-DET1024's approach

Both FIPS 204 and FIPS 205 also permit a fully deterministic variant (`rnd = {0}^32`) but
explicitly warn against it on platforms where fault or side-channel attacks are a concern.

FIPS 206 (FN-DSA) has not been finalised yet, but the PQC standardisation community has been
actively pushing for hedged signing to be the default. In an October–November 2025 thread on
the NIST PQC Forum, John Mattsson (Ericsson) explicitly raised the PS3/randomized-ECDSA
failure scenario and asked whether FN-DSA would hedge like ML-DSA: *"We hope it is hedged."*
Ray Perlner (NIST) responded: *"We welcome feedback on John Mattsson's suggestion that hedged
signing be preferred over plain randomized signing"* — confirming NIST's direction.

Thomas Pornin proposed a concrete FN-DSA hedging formula in the same thread:

```
derived_seed = SHAKE256(SHAKE256(f || g)[40] || mu || rng_seed)[40]
```

This hashes the private key polynomials `(f, g)` first, then combines with the message hash `mu`
and fresh `rng_seed` — the same three-way structure as ML-DSA but memory-efficient for
constrained implementations since it avoids needing the full encoded private key in memory.

**Where hedged signing sits relative to the three-way tradeoff:**

| Approach | Entropy failure | Fault attack resistance |
|---|---|---|
| Pure randomized (standard Falcon) | Vulnerable | Strong — attacker can't predict nonce |
| **Hedged (FIPS 204/205/206 default)** | **Graceful degradation** | **Conditional — weakens only if entropy also fails** |
| Fully deterministic (FALCON-DET1024) | Immune | Weak — nonce always predictable |

Hedged signing narrows the fault attack exposure: triggering it requires both broken entropy AND
successful fault injection simultaneously, compared to FALCON-DET1024 where fault injection alone
is sufficient. For blockchain deployments where entropy quality is uncertain, hedged signing is
the more principled middle ground — and it is what NIST standardised, not pure randomness.

### "The blockchain industry doesn't always follow NIST"

Historically accurate (secp256k1, Keccak-256 with modified padding, RFC 6979 deterministic ECDSA).
However, these precedents apply most cleanly to internal protocol mechanisms and developer-facing
primitives. Signing schemes are user-facing identity primitives — the foundational thing every
wallet, exchange, and user directly interacts with. The case for standardisation is stronger here
than for internal mechanisms like VRF. Variant proliferation in signing schemes creates the
ecosystem fragmentation that the blockchain industry has repeatedly struggled with.

### "We have a tried and trusted implementation in production for years"

The implementation is mature. But "tried and trusted" in the context of post-quantum security
means resistance to a quantum adversary — which no scheme has demonstrated because no sufficiently
capable quantum computer exists yet. The claim is about implementation correctness, not about
delivering the fundamental promise of the scheme.

### "FN-DSA's non-determinism is a computation problem, not just an output difference"

This conflates two distinct notions. FN-DSA is fully computation-deterministic given a specific
nonce — the algorithm runs correctly and consistently. The non-determinism is in *choosing* the
nonce, not in the computation itself. Two FN-DSA signatures on the same message produce different
bytes because different nonces were drawn; that is expected correct behaviour, not a computation
failure.

The FPEMU concern in FALCON-DET1024 is the opposite: a function that *should* be reproducible
(same nonce, same message, same key) produces *different* outputs due to floating-point
discrepancies. That unintended inconsistency is what "Do Not Disturb" exploits — the structured
difference between two runs that should have been identical. FN-DSA has no such exposure because
different outputs from different nonces are by design: there is no "expected identical output"
against which a discrepancy can be measured and exploited.

### "Cross-machine floating-point determinism requires FPEMU"

FPEMU is a *computational correctness* concern that exists across all Falcon variants, not a
property unique to the deterministic variant. Any Falcon implementation using native floating-point
on heterogeneous hardware risks producing slightly different intermediate values due to FPU
differences, compiler optimisations (FMA reordering, extended x87 precision), or AVX2 vectorisation.
This is true whether the scheme is randomised or deterministic.

What changes with FALCON-DET1024 is the *consequence* of FP divergence. In randomised Falcon, if
two devices produce slightly different FP results, both outputs are still valid independent
signatures — different bytes, both acceptable to a verifier. In deterministic Falcon, two signing
calls on the same key and message are supposed to produce identical bytes. FP divergence between
devices breaks that guarantee and, as the "Do Not Disturb" paper demonstrated, can expose the
private key when the same input is processed with different FP behaviour. FPEMU ensures single-machine algorithmic consistency in both cases, but the stakes differ: in the
randomised case, cross-device FP divergence produces different-but-valid signatures — a non-issue;
in the deterministic case, it breaks the fundamental invariant and enables the Do Not Disturb
attack, making it load-bearing for security.

The spec mandates `FALCON_FPEMU=1` as the solution, with a measured performance cost: signing is
**~15x slower** with FPEMU enabled (key generation ~2x slower; verification unaffected since it
uses no FP). The spec's own warning is precise: *"the same private key should not be used to sign
the same message digest using functionally inequivalent sampling procedures."*

FN-DSA implementations can use native `f64` on 64-bit platforms (consistent via strict IEEE-754)
and integer emulation only on 32-bit. Modern blockchain node hardware is 64-bit. The cross-machine
consistency argument does not favour FALCON-DET1024's blanket emulation approach.

---

## Protocol Migration Implications

Algorand's current migration path is built on FALCON-DET1024 (via account abstraction and state
proofs) with native protocol Falcon accounts as the next step. The considerations below describe
that landscape. FN-DSA is noted where it would offer a concrete improvement over the deterministic
variant; otherwise the discussion applies equally to both Falcon variants.

### Account Address Scheme

Ed25519's 32-byte public key IS the account address. A Falcon public key (1793 bytes for n=1024)
cannot serve this role directly. The address must be derived as a hash of the public key,
following Algorand's existing domain-separation pattern:

```
address = H("PqAddr" || pubkey_bytes || salt)
```

A deterministic salt is required to ensure the resulting address is off-curve — not
interpretable as a valid Ed25519 public key, which would reintroduce the accidental key
vulnerability. The salt must be selected by a protocol-defined deterministic rule (for example,
the lowest integer value that produces an acceptable address), so that anyone who knows the
Falcon public key can independently derive the canonical address. Without a canonical derivation
rule, the same public key could correspond to multiple possible addresses, making the account
model ambiguous for users, wallets, and validators.

This is consistent with how Algorand already derives addresses for MultiSig accounts
(`SHA512/256("MultisigAddr" || ...)`) and LogicSig accounts (`SHA512/256("Program" || bytecode)`).
This design is also quantum-safe against Grover's algorithm: a 32-byte SHA-512/256 output with
clear domain separation retains a very large security margin against targeted second-preimage
attacks, which is the relevant quantum threat for hash-derived addresses.

For a hybrid transition period, the address could commit to both keys:

```
address = SHA512/256("HybridAddr" || ed25519_pubkey || falcon_pubkey)
```

This enables the dual-signature approach (requiring both Ed25519 and Falcon signatures)
during the transition, with the address unchanged regardless of which key is eventually retired.

### Verification: Stateless vs Stateful Design

Ed25519 verification is pure computation — the address bytes ARE the public key. A native Falcon
account uses a hash-derived address, so the 1793-byte public key is not recoverable from the
address alone. The verifier needs the key made available somehow. Two designs exist:

**Stateless design** — each transaction carries the sender address, the Falcon public key, and
the signature. The verifier checks that the public key derives the sender address, then verifies
the signature. No ledger state lookup is required. Verification is fully parallelizable and
independent of ledger state. The drawback is transaction size: carrying a 1793-byte public key
on every transaction increases fees under a bytes-based fee model.

**Stateful design** — the account record stores the Falcon public key after its first
introduction. Subsequent transactions carry only the signature; the verifier looks up the public
key from account state:

```
address → state read → pubkey → verify(sig, pubkey, message) → valid/invalid
```

This reduces transaction size after the first use. The drawback is that signature verification
becomes dependent on a ledger read when the public key is omitted. The key can be implemented
as soft state: if the account is closed, the public key can be re-supplied via a later stateless
transaction. Potential mitigations for the state read overhead:
- **Pre-fetching**: batch all state reads for a block's transactions in parallel before the
  verification pass.
- **Key caching**: active accounts with stable Falcon keys have very high cache hit rates.

The stateless design is the simpler and more parallelizable path; the stateful design reduces
per-transaction cost at the price of a ledger dependency. The choice has not been finalized for
native Falcon protocol accounts. Both designs apply equally to FALCON-DET1024 and FN-DSA.

### Block Structure: Signature Storage

Falcon signatures represent roughly a 20x increase over Ed25519's 64 bytes. FALCON-DET1024
uses variable-length compressed signatures averaging ~1222 bytes (maximum of 1423 bytes).
FN-DSA uses a fixed padded formatof exactly 1280 bytes. Both are in the same range for
storage purposes, but FN-DSA's fixed size simplifies block capacity planning. FALCON-DET1024
can also produce fixed-size CT-format signatures at 1538 bytes via a post-signing re-encoding
step that requires no re-signing — a 258-byte premium over FN-DSA's padded format in exchange
for fixing the variable-length gap. A SegWit-style separation addresses both block capacity
and long-term storage for either variant:

```
Block {
    Header {
        txn_root   // existing — Merkle root of transaction payloads
        sig_root   // NEW — Merkle root of all signatures, same ordering
    }
    Body(txns)     // permanent — sender, receiver, amount, etc. (no signatures)
    Witness        // prunable after BA* finality — actual signature bytes
}
```

Algorand already computes TxID from transaction fields only —
`TxID = SHA-512/256("TX" || msgpack(tx_fields))` — with signatures carried separately in the
`SignedTransaction` wrapper `{txn: Transaction, sig: Signature}`. TxID computation does not need
to change for either Falcon variant. What changes is the storage and transmission cost of the
signature bytes themselves: ~1280 bytes vs 64 bytes per transaction. The witness separation
addresses that: after Algorand's instant BA* finality, the witness section can be pruned by most
nodes. The `sig_root` persists permanently as proof that all signatures were valid. Anyone needing
to verify a historical signature requests it from an archival witness node along with a Merkle
inclusion proof, verifies the proof against the known `sig_root`, then verifies the signature
against the transaction's sender's registered pubkey.

Algorand's existing state proof infrastructure (vector commitments, Merkle trees) provides the
exact tooling this requires — it is an extension of a pattern already built into the protocol.

### Archival Storage

Archival nodes that retain the full witness section face a 20x increase in signature storage:
roughly 40 TB/year at 1,000 TPS vs ~2 TB/year today. Falcon-1024 signatures are a tightly
bit-packed encoding of a short lattice vector — cryptographically uniform bytes with no
exploitable patterns, so generic compression produces no meaningful reduction. Either way,
~1280 bytes is effectively the floor per signature.

The structural solution is to avoid storing individual signatures in archival nodes at all.
The SegWit-style witness separation described above already separates signature bytes from
transaction data. After BA* finality, an aggregator generates a ZK proof — using a
quantum-safe system such as LaBRADOR — over the full block's signatures before they are
pruned. This proof attests that every signature in the block was valid against its
corresponding public key and message, without requiring the individual signatures to be
retained. The `sig_root` Merkle commitment persists permanently in the block header,
and the aggregate proof replaces the witness section for long-term archival.

The storage economics are significant: ~13 MB of individual Falcon signatures per 10,000
transactions collapses to a single ~74 KB aggregate proof. Archival nodes store the compact
proof and the `sig_root`; the raw witness bytes need not survive beyond the window needed for
proof generation. Anyone wishing to verify a specific historical signature can request the
individual signature and its Merkle inclusion proof from a full witness node, verify the
inclusion against the known `sig_root`, and then verify the signature directly — the archival
proof attests to the set, the `sig_root` attests to each member of the set.

This approach is not speculative infrastructure — it is a direct application of the same ZK
aggregation properties that make FALCON-DET1024's determinism valuable. The `sig_root`
commitment model and the state proof vector commitment infrastructure already present in
Algorand's protocol provide the exact tooling it requires.

### Multi-Signature Implications

Multisig accounts face two distinct quantum risks requiring separate solutions:

- **Risk 1 — Accidental address**: the multisig address is hash-derived; if it decodes as a
  valid Ed25519 public key, a CRQC could derive a matching private key and collapse the
  threshold account into a single-key account. Addressable with the same salting or typing
  strategy used for LSig and Application accounts.
- **Risk 2 — Sub-signer exposure**: raw Ed25519 public keys are embedded as sub-signers and
  revealed on-chain at spend time. A CRQC can target each individually; compromising enough
  to meet the threshold gives full control. Rekeying does not address this — sub-signers are
  keys embedded in a multisig template, not accounts. Fully resolving Risk 2 requires a new
  multisig version or a threshold design built on PQ primitives.

Falcon has no algebraic linearity equivalent to Ed25519, which adds two engineering
constraints for any native Falcon multisig:

- **Key payload growth**: each spending transaction must carry N public keys inline
  (N × 1793 bytes vs. N × 32 bytes today).
- **No native aggregation**: each co-signer contributes a separate ~1280-byte signature;
  an M-of-N threshold produces M independent signatures, all of which must be verified.

These are engineering constraints, not security problems. ZK aggregation of the M
verification proofs is the most practical longer-term mitigation — see the
[ZK proof aggregation](#use-cases-where-signing-determinism-is-genuinely-required)
discussion for the circuit-level analysis.

One advantage of the LSig + opcode model over native multisig is crypto agility: a threshold
policy expressed as an LSig can call any combination of verification opcodes, mixing schemes
freely — Ed25519, Falcon, SQIsign, or any future scheme with an opcode — in a single
threshold. Native multisig is structurally bounded by whatever schemes the protocol supports
at a given time; upgrading to a new scheme requires a protocol change. An LSig-based threshold
requires only a new opcode. For multisig specifically, this is not just flexibility — it is
the only path to scheme-agnostic threshold policies without a protocol redesign each time
the PQ landscape advances.

### Migration Path and Hybrid Period

Algorand's existing Ed25519 accounts cannot be migrated atomically — there is no mechanism to
force all existing key holders to re-key simultaneously. A complicating factor is that Algorand
addresses are not self-describing: the ledger only learns an account's control type (single-sig,
multisig, LogicSig, application) when the account first performs a valid action. Before that,
the address alone gives no indication of how it is controlled. This means a single protocol rule
cannot cleanly cover all account types at once — migration strategy must differ by account type,
and must handle already-existing accounts, unfunded accounts, and addresses computed before their
corresponding application exists. A realistic migration path requires a hybrid period:

1. **Single-sig account migration via rekeying**: Algorand's rekeying feature separates an
   account's public address from its current authorizer. A user migrating to Falcon can keep
   the same address while changing the authorizer: create a Falcon-controlled LSig account
   with off-curve address, then rekey the existing Ed25519 account to that Falcon authorizer.
   For a native Falcon protocol account, the longer-term design registers a Falcon public key
   alongside the existing Ed25519 key, with an address committed to both:
   `SHA512/256("HybridAddr" || ed25519_pk || falcon_pk)`, and both signatures required
   simultaneously — protecting against either scheme failing independently. The current Falcon
   account abstraction requires a 4-transaction group rather than a single transaction due to
   the pooled bytes budget for LSig program and arguments; resolving this friction requires
   either a protocol upgrade to increase LSig size limits or native Falcon account support.

2. **Deprecation window**: Announce a future block height after which Ed25519-only signatures
   will no longer be accepted for new transactions. Accounts that have not registered a Falcon
   key by that block height would need to migrate before spending.

3. **Logic Signature account hardening**: Because LSig addresses are derived from program
   bytecode, a harmless salt can be added until the address is off-curve — no protocol upgrade
   required. This is already used in the LSig-based Falcon account abstraction; the long-term
   goal is for the assembler to search for an off-curve address automatically as the default.

4. **Application account hardening**: Application account addresses are derived from the
   Application ID (a protocol counter), not from program code, so the LSig salting approach
   does not apply. Two protocol-level options are under consideration: salting the address
   derivation at creation time, or recording account type in the ledger to reject Ed25519
   signatures for known application-controlled addresses. Neither is finalized; both require
   protocol changes.

5. **Quantum-vulnerable account handling**: Accounts that never registered a Falcon key and
   whose Ed25519 private key may be at quantum risk represent the hardest migration challenge.
   This is an unsolved problem common to all blockchain PQC migrations — there is no safe way
   to migrate an account whose private key is unknown or inaccessible.

One concrete mechanism that avoids both the panic migration and forced lockout failure modes is
**lazy migration**: accounts can pre-declare a post-quantum fallback authorizer while continuing
normal operation. If the network later needs to disable a vulnerable authorization path, the
protocol switches only opted-in accounts to their pre-declared PQ authorizer. This gives users
time to prepare before urgency arrives, and avoids imposing a one-size-fits-all migration on
accounts with complex custody, governance, or application dependencies.

**LSig + opcode architectural model.** An alternative to protocol-level PQ account types is
to rekey accounts to an LSig that calls a new protocol verification opcode — e.g., a
`falcon_verify` or `pq_verify` opcode added via consensus upgrade. The LSig is the delivery
container; the opcode is the security primitive. Scheme upgrades then require only new
opcodes, not changes to transaction format, block structure, or sigType fields — an unlimited
number of PQ schemes can be supported without ever changing the shape of a transaction. The
rekey model also supports incremental scheme migration: an account can rekey to a
`pqv1`-calling LSig today and rekey again to a `pqv2`-calling LSig when a better scheme
matures, with no address change and no disruption to dependent applications at any step. Each
additional scheme requires only one new consensus change (the opcode), not a full protocol
redesign — the compounding advantage grows with every scheme iteration.

One design tension in this model: an LSig account is arbitrary code, and a program that
returns `int 1` unconditionally is a valid LSig — it approves every transaction. Without
protocol enforcement, a "PQ account by convention" provides no protocol-level security
guarantee; the security depends entirely on what the LSig code actually calls. Two mechanisms
address this without requiring a full native account type:

- *Mode or pragma restriction*: a lightweight protocol mechanism that marks certain LSig
  programs as operating in a restricted mode where only signature verification opcodes are
  permitted. The protocol enforces the constraint at the program level without committing to
  any specific scheme — the opcode, not the account type, is what the protocol knows about.

- *Canonical standard program*: rather than each wallet implementing its own LSig, one
  audited program per scheme is published as the standard — the existing Falcon LSig becomes
  `pqv1`, a future scheme gets its own canonical program. Wallets and explorers verify against
  the known program hash. Security comes from the audited program rather than from protocol
  enforcement of a sigType field.

**LSig bytecode overhead is negligible.** A concern with the LSig model is that wrapping
verification in an LSig adds size overhead on top of already large PQ signatures and keys. In
practice the LSig bytecode is small: a real LSig doing more than a simple signature check runs
approximately 238 bytes including its own signature. Falcon signatures are ~1,280 bytes and
Falcon public keys are ~1,793 bytes. The LSig wrapper contributes less than 10% additional
overhead and is not the binding size constraint — the PQ key and signature sizes dominate
regardless of delivery mechanism.

**Stateful public key storage applies to both paths equally.** For PQ schemes, the public key
is too large to embed in every transaction (1,793 bytes for Falcon-1024 vs 32 bytes for
Ed25519). Both the native protocol approach and the LSig approach converge on the same
solution: store the public key in the ledger and have the address commit to it. This is
exactly how LSig accounts already work today — the address is a hash of the program, which
commits to the verification logic. A PQ LSig address commits to both the program and the
public key stored alongside it. The native protocol path needs to solve the same stateful read
problem independently; it does not eliminate the ledger-read requirement, it just moves where
in the stack the read happens.

**Delegated LSig is a concrete capability gap.** A delegated LogicSig is a TEAL program the
account owner signs with their private key, granting anyone holding it conditional spending
authority over that account — for example, authorising a utility company to collect up to a
fixed amount every N rounds without requiring the owner's involvement at each payment. The
delegation is possible because the account has a private key to sign the TEAL program with.
An LSig-based PQ account has no such private key — its authorization is itself a TEAL program.
There is nothing to sign the delegation with. Native PQ accounts, which hold a Falcon private
key, can sign delegated LogicSigs; LSig-based PQ accounts structurally cannot. This is a
genuine capability gap that the LSig + opcode model does not close.

**Opcodes are also permanent.** A counterpoint to the "fewer changes" argument: once an
opcode is deployed on-chain, every node must support it forever — the same permanence
obligation as a native sigtype. Adding `falcon_verify` as an opcode is an enshrinement in the
same sense as adding Falcon as a native account type; the difference is in which layer the
commitment lives, not in whether a commitment is made.

**Opcode-first, then native promotion — a two-stage framework.** The debate resolves more
cleanly as a staged path than as a binary choice. The `ecdsa_verify` opcode is the existing
precedent: in production use for EVM-compatible accounts without ever being promoted to a native
account type, demonstrating the opcode stage works sufficiently as the intials step for deployment.

1. *Opcode stage* — expose the scheme as a `<pq-dsa>_verify` AVM opcode. Developers can build
   LSig-based accounts and production applications, the ecosystem accumulates real-world
   experience, and no protocol-level commitment to the scheme is made. This avoids enshrining
   a scheme before its behaviour under production conditions is well understood.

2. *Native promotion* — once the scheme has demonstrated maturity, broad adoption, and fit with
   Algorand's throughput and latency constraints, promote it to a native type on the protocol
   layer. This removes the LSig wrapper and ARC-convention requirements, gives the protocol
   direct enforcement of the cryptographic check, and makes the scheme straightforward for
   wallets, custody providers, and exchanges to support without custom tooling.

`Falcon-DET1024` is the current baseline under this framework — already deployed in State Proof
since 2022, already available as an AVM opcode, and already proven at production scale. Promoting it
to a native PQ account type is the natural continuation of that trajectory. Schemes at earlier
stages of maturity are better introduced at the opcode stage first, where the ecosystem can
evaluate them before any protocol commitment is made.

### Batch Verification Loss

Ed25519 supports batch verification — verifying N signatures together via a single multi-scalar
multiplication is faster than N individual verifications. Falcon has no equivalent; each
signature must be verified independently. The throughput impact is partially self-offsetting:
the ~20x signature size increase reduces the number of transactions that fit in a block, meaning
fewer total verification operations per block even without batching. Mitigations:
- **Parallel verification**: Falcon verifications are fully independent and parallelise trivially
  across CPU cores. Algorand's ledger evaluation already implements this pattern — signature
  verification runs concurrently with transaction state evaluation, parallelised across the full
  block payset using a goroutine pool. Any native Falcon scheme slots into this existing
  infrastructure without architectural changes; the parallelism already exists and only the
  per-signature verification function changes.
- **ZK proof aggregation** (longer-term): a block producer verifies all transaction signatures
  and generates a single proof attesting their validity. Validators verify one proof instead of
  N signatures, making per-transaction verification overhead essentially zero. Active research
  area; circuits for lattice-based signatures are not yet efficient enough for production but
  the direction is clear.

  For end-to-end PQ security the aggregation scheme must itself be quantum-safe — pairing-based
  SNARKs (Groth16, PLONK/KZG) are quantum-vulnerable and replace one attack surface with
  another. The quantum-safe options are STARKs (hash-only, no trusted setup) and lattice-based
  arguments of knowledge such as LaBRADOR (IACR ePrint 2024/311).

  FALCON-DET1024 is better positioned for both paths than FN-DSA. The difference is in witness
  composition: with FN-DSA the prover must supply `w = (s1, s2, r)` — the random salt is a
  private witness — and the circuit must evaluate `H(r, m)` internally using SHA-3/Keccak,
  which requires tens of thousands of constraints per instance. With FALCON-DET1024 the witness
  shrinks to `w = (s1, s2)` — the syndrome `H(fixed_salt, m)` is a public constant computed
  outside the circuit entirely. SHA-3 never enters the circuit. This eliminates the dominant
  per-instance constraint cost, reducing proving time by an order of magnitude across a full
  block's worth of signatures. The advantage is proof-system-agnostic: it applies equally to
  STARKs and lattice SNARKs. See the
  [ZK proof aggregation use case](#use-cases-where-signing-determinism-is-genuinely-required)
  for the full circuit analysis including the modulus mismatch constraint.

---

## Post-Quantum VRF

Algorand's cryptographic sortition — the core, lottery mechanism that selects validators
for its Pure Proof-of-Stake (PPoS) consensus — depends on a Verifiable Random Function
(VRF) randomly selecting block proposers and committee members each round. The current
implementation is a tailored variant of **ECVRF-ED25519-SHA512-Elligator2**, closely aligned
with but predating [RFC 9381](https://www.rfc-editor.org/rfc/rfc9381) (Goldberg, Reyzin,
Papadopoulos, Vcelak — IRTF, August 2023). Algorand built this into the protocol in 2018–2019
against the earlier draft (draft-irtf-cfrg-vrf-03) and curtailed the broader standard in
several ways for high-throughput ledger performance: parameters are hardcoded for the consensus
engine rather than kept general, the hash-to-curve step uses a custom try-and-increment loop
optimised for Ed25519 rather than the full IETF suite, and the proof byte layout is trimmed
to fit the AVM's `vrf_verify` opcode budget. The result is a VRF that is functionally
equivalent to the IETF construction for Algorand's purposes but is not a drop-in implementation
of RFC 9381. Its core operation is `Gamma = x·H`: the secret scalar multiplied by a curve
point derived from the input. The output `beta = Hash(Gamma)` is uniquely determined and
pseudorandom because discrete log makes `Gamma` indistinguishable from a random curve point.
All valid proofs for the same (SK, input) converge on the same `beta` — enforced algebraically
and strengthened by an additional check: Algorand's verification explicitly rejects any proof
where `Gamma` is not on the main elliptic curve subgroup or is of low order, preventing
subgroup-confinement attacks that have no equivalent safeguard in the Falcon norm check.

A VRF must satisfy five properties for use in sortition: **Verifiability** — the output is
valid if and only if it was produced by the correct secret key; **Determinism** — the same
(SK, input) always yields the same output, preventing a signer from running the algorithm
repeatedly to obtain a favourable committee weight; **Uniqueness** — it must be infeasible to
produce two different valid proofs that yield different outputs, so a signer cannot present a
cherry-picked alternative; **Pseudorandomness** — the output is computationally
indistinguishable from random without the secret key; **Total Ordering** — outputs are strictly
rankable so committee winners can be selected by threshold.

Neither Falcon variant satisfies all five:

| VRF Criterion | FALCON-DET1024 | FN-DSA |
|---|---|---|
| Verifiability | ✓ — ring equation and norm check hold; verification well-defined | ✓ — verification well-defined for any valid signature |
| Determinism | ✓ — nonce derived from SK and input; same (SK, alpha) always yields same beta | ✗ — random nonce produces different output each call; enables rank grinding |
| Uniqueness | ✗ — norm check `\|\|(s1,s2)\|\|² ≤ β` admits multiple valid short vectors with different hashes | ✗ — same structural flaw, compounded by non-determinism |
| Pseudorandomness | ✗ — deterministic sampling breaks the GPV/Rényi argument; heuristic only | ✗ — Paper 2024/1769 proves EUF-CMA (unforgeability), not VRF pseudorandomness; no published proof shows H(σ) is indistinguishable from random given VK |
| Total Ordering | ✗ — uniqueness failure lets malicious validators mine alternative short vectors for better rank | ✗ — non-determinism directly enables rank grinding |

Both variants fail pseudorandomness, for different reasons. FALCON-DET1024 because deterministic
sampling breaks the GPV/Rényi argument the security proof depends on — heuristic only. FN-DSA
because Paper 2024/1769 proves EUF-CMA (unforgeability), which is a distinct property from VRF
pseudorandomness: no published proof shows that H(σ_FN-DSA) is computationally indistinguishable
from random given VK. Both fail uniqueness for the same structural reason — Falcon's norm check
`||(s1, s2)||² ≤ β` is an inequality admitting multiple valid short vector solutions for the
same syndrome, whereas ECVRF's `Gamma = x·H` is algebraically rigid with exactly one solution
for any given `(x, H)`.
For FALCON-DET1024 the uniqueness failure is not a trivial exploit: a malicious validator would
need to implement non-deterministic Falcon sampling with different randomness to enumerate
alternative short vectors, bypassing the deterministic signing API entirely. For FN-DSA the
failure is more direct: the honest signing algorithm already produces different outputs on each
call. In both cases the property does not hold against a determined adversary.

Lattice-based VRF constructions face their own distinct limitation. *Practical Post-Quantum
Few-Time VRF* (FC 2021, improved CRYPTO 2023) is the leading practical lattice-based candidate,
but it can generate only **one output per key pair** — requiring full key rotation after every
evaluation. For blockchain consensus where validators evaluate the VRF every block, this is
operationally impractical. This constraint is not a parameter choice; it is structural to the
lattice-based construction. It confirms that the lattice path to a PQ VRF has fundamental
obstacles beyond the Falcon-specific issues analysed above, and explains why hash-based
constructions have become the more immediate research direction.

Hash-based constructions sidestep the lattice difficulties entirely. Rather than scalar
multiplication on a curve, the VRF output becomes a purely hash-based evaluation:
`outvrf = H3(H2(vsk, H1(m)))`. Uniqueness follows from hash collision resistance rather than
algebraic rigidity; pseudorandomness follows from pre-image resistance (Grover's algorithm
reduces 256-bit pre-image resistance to 128-bit post-quantum security, which remains
acceptable); a quantum-safe zero-knowledge proof proves the prover knows `vsk` consistent with
their public key without revealing it. All five VRF criteria are satisfied. The main trade-off
is proof size.

**ZK proof system for hash-based VRF.** In XM-VRF, no separate outer ZK layer exists. The
XMSS authentication path IS the structural proof of key knowledge: it proves that the leaf
containing the one-time key is committed in the Merkle tree whose root is the public key,
without revealing the underlying secret key material — the leaf index is included in the
proof as it is required for verification. The ~1.3–5.5 KB proof is the
combined WOTS+ signature and authentication path — not a wrapper around a ZK proof. This is
hash-native all the way down. If future proof compression below that floor is desired, a
**STARK** (FRI-based, hash-only) is the coherent outer compression layer: it introduces no
new hardness assumption beyond what the VRF already requires. A pairing-based SNARK would
introduce quantum-vulnerable elliptic curve assumptions on top of a quantum-safe construction,
defeating the purpose. A lattice SNARK like LaBRADOR is equally inappropriate here — it is
designed for proving knowledge of short lattice vectors, not hash chain evaluations. The
domain mismatch would make the circuit complex and the proof larger, not smaller.

*Post-Quantum VRF and its Applications in Future-Proof Blockchain System* (arXiv 2109.02012)
implemented this construction explicitly for Algorand, modelling the sortition election directly as
`VRF(h(Bi), round, pk, σ) < T` and benchmarking against Algorand's VRF. Using ZKBoo/ZKB++
as the zero-knowledge proof system, proof sizes run 128–246 KB — adding approximately 824 KB
per block (~8% of Algorand's 10 MB block size).

*Key Updatable Hash Based VRF* (IACR ePrint 2026/052)
significantly improves this by replacing ZKBoo with an XMSS-based construction. The proof
— `d WOTS+ signatures + d XMSS authentication paths` — is `2(l + h/d) × λ/8` bytes. The
paper presents two constructions: a general d-layer framework and a simplified 2-layer version
(d=2) targeted specifically at Algorand's committee selection, where each user evaluates
`(y, π) ← XM-VRF.Eval(sk, Q)`, checks `y ∈ [0, P]` against their stake-proportional
threshold, and broadcasts if selected. Beyond proof size, XM-VRF introduces key updatability
(the secret key auto-updates after each evaluation via a forward-secure stateful PRG) and
faster key generation via multi-layer XMSS trees. The paper also patches a 2025 attack —
*Breaking X-VRF* (FC 2025) — that broke uniqueness in the predecessor scheme by exploiting
a WOTS+ flaw.

The Algorand-targeted implementation (N=32, W=16, L=67, H=22, D=2) produces
**4,996-byte proofs** and supports **2^22 = 4,194,304 evaluations** (~137 days at 2.82s/block)
from a single key pair. Keygen takes ~3.57s (vs 240–360s for ECVRF's 30-day key),
eval ~1.4ms, verify ~700µs. Key lifetime is bounded by H, not unbounded; the paper's general
framework supports larger H at proportionally larger proof cost.

One deployment concern: a counter `ctr` tracking the current XMSS leaf index must be
maintained across all evaluations. If a validator node crashes and restores from a stale
backup, it could reuse a WOTS+ one-time key — WOTS+ is designed for single use, and reuse
could violate the uniqueness property. For the Algorand-specific deployment this is resolved
without new ledger state: the expected leaf is `expected_ctr = current_round - VoteFirstValid`,
derivable by any verifier from the existing keyreg fields. A proof with the wrong counter is
rejected; a validator cannot choose a different leaf for a given round. State rollback
grinding — signing the same round from multiple leaf positions — is closed by the math rather
than by an honour system or hardware enclave.

**Lattice-based Ring VRFs — anonymity ECVRF cannot provide.** A separate research direction
addresses an identity exposure property that hash-based constructions above do not eliminate:
in Algorand's current sortition, standard VRF verification reveals which participant produced
the output. Algorand's design significantly mitigates the practical risk — cryptographic
self-selection means a participant reveals their selection at the exact moment they broadcast
their vote, so by the time an adversary learns who was chosen, the participant has already
acted. Sub-3-second finality leaves no practical window for targeted interference. However,
the exposure is not zero, and Ring VRFs eliminate it entirely rather than relying on timing.
*Lattice-based Ring Verifiable Random Functions* (IACR ePrint 2026/772, Xu, Esgin, Steinfeld
— Monash University, 2026) formalises Ring VRFs, where a member of a public key ring proves
a valid VRF output was produced by some ring member without revealing which one.
The paper explicitly cites Algorand's sortition as the motivating application.

Two lattice-based instantiations are provided: **RVRF[LaV]** using the long-term lattice VRF
LaV (CRYPTO 2023, unlimited evaluations per key, base proof ~10.27 KB) and **RVRF[LB-VRF]**
using the few-time lattice VRF LB-VRF (FC 2021, k evaluations per key, base proof ~4.94 KB).
LaV achieves uniqueness via a lattice pseudorandom function — deterministic by construction —
confirming that lattice math is not fundamentally incompatible with VRF requirements.

The critical limitation is proof size: both constructions scale **linearly with ring size N**,
as `|π| = N × (16 bytes + |σbase|)`. Concretely:

| Ring size N | RVRF[LB-VRF] | RVRF[LaV] |
|---|---|---|
| 8 | ~40 KB | ~82 KB |
| 32 | ~159 KB | ~329 KB |
| 256 | ~1.24 MB | ~2.57 MB |

For Algorand's committee of potentially hundreds to thousands of members, linear scaling is
impractical. The paper identifies **sublinear Ring VRF** via one-out-of-many (OOM) proofs —
polylog(N)-size membership proofs rather than N base-VRF proofs — as the required future
direction, explicitly left as open work. The paper also identifies and addresses **ring
grinding**: without binding the ring into the evaluated input, a malicious member could try
different ring configurations to obtain a favourable VRF output. The fix is `µ = x ||
Hash(Canon(R))` — the canonical ring encoding is hashed into the input, so no ring
configuration manipulation yields a different output for the same key and input.

**ZK proof system for Ring VRF — OOM proofs are a distinct problem.** The sublinear Ring VRF
future direction requires one-out-of-many (OOM) proofs: a prover commits to one of N public
keys and proves knowledge of the corresponding secret key, without revealing which one. This
is a *set membership* statement — structurally different from both signature aggregation and
basic VRF proof compression. LaBRADOR proves knowledge of Falcon short vectors (a lattice
arithmetic statement) and is not suited for set membership. FRI-based STARKs can express
membership checks but do not have established OOM constructions optimised for lattice public
key sets. Lattice-friendly OOM proofs exist in the literature (based on commitment opening
arguments over module lattices) but none have reached the efficiency level required for
per-round Algorand committee sizes. This is an open research problem independent of both the
LaBRADOR aggregation track and the STARK compression track.

**AVM integration — opcode cost.** The existing `vrf_verify` opcode takes three stack inputs
— message (variable), proof (80 bytes fixed), public key (32 bytes) — and returns a 64-byte
VRF output plus a boolean. Its opcode cost is 5,700 AVM compute units, one of the most
expensive opcodes, because ECVRF-ED25519 involves elliptic curve scalar multiplications.
A `pq_vrf_verify` opcode for a hash-based scheme would be significantly cheaper: XM-VRF
verification is entirely hash-based, and SHA-256 runs 100–200x faster than an EC scalar
multiplication — a native opcode would likely land in the **1,000–2,000 unit range**, shifting
the overhead from computation to data. SHA-256 is the natural choice for XM-VRF in this
context for three compounding reasons: modern server and consumer CPUs carry dedicated
SHA-256 silicon (Intel SHA Extensions, ARMv8 Cryptography Extensions), making it faster in
practice than software-optimised alternatives like BLAKE3; proof size scales directly with
hash output width, so SHA-256's 32-byte nodes keep authentication paths roughly half the size
of SHA-512's 64-byte nodes — directly relevant to Algorand's block space constraints; and
SHA-256 delivers exactly 128 bits of post-quantum security against Grover's algorithm, which
is the accepted target for the foreseeable future. XM-VRF is algorithm-agnostic and would
function correctly with any collision-resistant hash, but SHA-256 is the optimal choice on
all three axes simultaneously. A randomness beacon migrating from ECVRF to a hash-based PQ
scheme requires all three layers to update simultaneously: the protocol (new opcode via
consensus upgrade), the off-chain oracle (switch from ECVRF to XM-VRF proof generation),
and any smart contracts using the beacon. Immutable contracts that cannot be upgraded remain
permanently tied to `vrf_verify`.

| Parameter | Current `vrf_verify` | Estimated `pq_vrf_verify` |
|---|---|---|
| Standard | VrfAlgorand (ECVRF-ED25519-SHA512-Elligator2, draft-irtf-cfrg-vrf-03) | XM-VRF or equivalent hash-based scheme |
| Proof input (B) | 80 bytes (fixed) | 4,996 bytes (Algorand-targeted: N=32, W=16, L=67, H=22, D=2; parameter-dependent, see below) |
| Public key input (C) | 32 bytes | 64 bytes (`root \|\| chain_key`) |
| VRF output (X) | 64 bytes | 32–64 bytes (hash output) |
| Opcode cost | 5,700 | ~1,000–2,000 (estimated) |
| Min. app calls (opcode budget) | 9 (9 × 700 = 6,300 ≥ 5,700) | 2–3 (estimated) |
| Quantum safe | ✗ | ✓ |

**Proof size — parameter-dependent.** XM-VRF Table 3 gives the exact proof formula:
`d(l + h/d)` strings of λ bits, where d is the number of XMSS layers, h is the total tree
height, l is the WOTS+ chain count, and λ is the security parameter. The paper's own
efficiency examples use n=40, l=10, d=4. At λ=256 bits (32 bytes per string):

| Parameters | Proof size | Fits in one app call (≤ 2,048 bytes)? |
|---|---|---|
| l=10, h=40, d=4, λ=256b | 4(10+10)×32 = **2,560 bytes** | ✗ (just over) |
| l=10, h=40, d=2, λ=256b | 2(10+20)×32 = **1,920 bytes** | ✓ |
| l=10, h=40, d=4, λ=128b | 4(10+10)×16 = **1,280 bytes** | ✓ |
| l=67, h=40, d=2, λ=256b | 2(67+20)×32 = **5,568 bytes** | ✗ |
| **l=67, h=22, d=2, λ=256b** | **2(67+11)×32+4 = 4,996 bytes** (Algorand-targeted) | ✗ (exceeds 4,096-byte stack limit; box storage required) |

The value of l depends on the WOTS+ message length m and Winternitz parameter w
(l = l1 + l2 where l1 = ⌈m/log w⌉). The paper consistently uses l=10 in examples,
which corresponds to signing a 32-bit message with w=16 — suggesting the VRF input is
hashed down before WOTS+ signing. With that parameterization and d=2, the proof is
approximately **1.9 KB** and fits within a single app call's 2,048-byte argument budget.
With l=67 (standard WOTS+ for a 256-bit input, m=256, w=16) and the paper's reference h=40,
the proof reaches 5,568 bytes. The Algorand-targeted implementation uses h=22, giving
**4,996 bytes** — still exceeding both the 4,096-byte stack variable limit and the 2,048-byte
per-call argument limit, so box storage or sub-component chunking is required regardless.

**Proof delivery — AVM size constraints.** Two AVM limits apply independently: a 4,096-byte
maximum for any stack variable, and a 2,048-byte maximum for combined arguments per
individual app call transaction. Adding more app calls to a group pools the opcode budget
but does not increase the per-transaction argument limit. The current 80-byte ECVRF proof
trivially fits in one app call.

*With box storage (cleanest path):* the oracle writes the proof to a box (up to 32 KB),
and `pq_vrf_verify` accepts a box reference, reading the proof without loading it onto the
stack. All size constraints are bypassed.

*Without box storage, if proof ≤ 1,920 bytes (l=10, d=2):* the full proof fits as a single
argument in one app call. The verifier call passes proof + vk core + message — all within
2,048 bytes combined. Simplest possible path; requires no chunking.

*Without box storage, if proof ~2,560 bytes (l=10, d=4):* the proof slightly exceeds one
app call's argument budget but fits on the stack (under 4,096 bytes). Split across two app
calls using `gload` (which lets a transaction read another transaction's scratch space within
the same group): one call passes the first 2,048 bytes, a second call passes the remaining
~512 bytes, and the verifier concatenates and calls `pq_vrf_verify`. Three app calls total.

*Without box storage, if proof ~4,996–5,568 bytes (l=67, d=2, h=22 or h=40):* the full
proof exceeds both the 4,096-byte stack variable limit and the 2,048-byte per-call argument
limit. Individual WOTS+ signatures are 2,144 bytes (67×32) and auth paths 352 bytes (11×32
per layer at h=22). Chunking is required at the sub-component level across 5 app calls using
`gload`, with the opcode accepting σ1, Auth1, σ2, Auth2 as separate stack values rather
than a concatenated blob. This is the path required for the Algorand-targeted 4,996-byte proof.

**Backwards compatibility.** The existing `vrf_verify` is hardcoded to verify 80-byte ECVRF
proofs — it cannot verify XM-VRF proofs. Smart contracts using the randomness beacon must
be updated to call `pq_vrf_verify`; immutable contracts cannot migrate. Three approaches
for the transition:

- *Proxy/wrapper beacon contract*: if consuming contracts route randomness requests through
  an upgradeable beacon contract rather than calling `vrf_verify` directly, only the beacon
  contract needs updating — consumer contracts see the same interface unchanged.
- *Dual-beacon transition period*: run the ECVRF beacon and XM-VRF beacon in parallel,
  with the old beacon continuing to serve existing contracts until they can be migrated.
  Classical security is sufficient for the ECVRF beacon given current quantum timelines.
- *Format-detecting opcode*: update `vrf_verify` to detect proof format by size and route
  to the appropriate verifier. Avoids a new opcode but complicates the cost model and may
  not help contracts that hard-check proof lengths internally.

**Assessment — hash-based vs lattice-based for Algorand's VRF.**

For near-term deployment, hash-based wins on every practical axis. XM-VRF satisfies all
five VRF criteria, is explicitly designed and benchmarked for Algorand's sortition by two
independent research groups, and rests on the most conservative post-quantum assumption
available — hash function collision resistance. The Algorand-targeted parameter set (N=32,
W=16, L=67, H=22, D=2) produces 4,996-byte proofs; box storage or 5-call chunking is
required for AVM delivery, but verification itself is cheap (~700µs, entirely hash-based).
The statefulness concern (the `ctr` counter) is a real operational engineering challenge for
general deployments, but is closed in the Algorand context: the expected counter is
`current_round - VoteFirstValid`, derivable by any verifier from existing keyreg fields with
no new ledger state.

For the long-term, lattice-based Ring VRFs represent a more compelling vision. Algorand's
current ECVRF has an identity exposure property that hash-based VRFs inherit: broadcasting a
proof reveals which committee member was selected. Algorand's design largely mitigates the
practical risk — self-selection means revelation and action are simultaneous, and sub-3-second
finality leaves no practical window for targeted interference. Ring VRFs go further by
eliminating the exposure entirely rather than relying on timing, proving eligibility without
revealing identity. LaV (the long-term lattice VRF underlying IACR ePrint 2026/772) also eliminates
the statefulness problem entirely: standard key pair, no XMSS-style leaf counter. But linear
proof scaling with committee size makes current constructions impractical until sublinear
one-out-of-many proofs are standardised.

The reasonable path: deploy hash-based PQ VRF now as a practical replacement for ECVRF —
it solves the quantum threat with known-good security assumptions and manageable engineering
trade-offs. Then upgrade to sublinear lattice Ring VRF as that research matures, gaining
anonymity and removing statefulness as additional benefits. Waiting for the lattice answer
before deploying anything risks leaving the VRF quantum-vulnerable while the harder
cryptographic problem is still being solved.

**Hash-based VRF avoids expanding the consensus trust surface.** A more fundamental argument
for preferring hash-based VRF in the sortition layer is that it does not introduce a new
hardness assumption into the most sensitive component of the protocol. Algorand's consensus
already assumes hash functions are collision-resistant — that assumption underpins block
hashing, Merkle trees, state proofs, and address derivation. A hash-based VRF inherits the
same assumption without enlarging the trust base. A lattice-based VRF adds SIS/LWE hardness
specifically to the sortition mechanism — the component that determines who proposes and votes
on each block. This is not an argument against lattice-based VRFs as a research direction; it
is an argument for conservatism in the most critical protocol layer. The case holds even if
lattice-based proofs eventually become smaller: minimising the set of distinct hardness
assumptions in the consensus hot path is a defensible cryptographic design principle
independent of proof size metrics.

**AVM compatibility favours hash-based VRF.** A `pq_vrf_verify` opcode for a hash-based
scheme would build on hash primitives already present in the AVM as native opcodes: sha256,
sha512_256, sha3_256, keccak256, and sumhash512 (AVM v13+). Verification is entirely
hash-evaluation-based — no new arithmetic is required. A
lattice-based `pq_vrf_verify` would need polynomial multiplication, norm checks, and
lattice-specific arithmetic that do not exist in the AVM today, requiring additional new
opcodes beyond the verification opcode itself. Hash-based VRF is therefore more naturally
compatible with Algorand's current execution environment and represents a smaller surface area
for the consensus upgrade.

**ZK proof system requirements for VRF differ fundamentally from signature aggregation.**
Several properties of the VRF context set it apart from the signature aggregation context
discussed elsewhere in this document:

- *Hot consensus path.* VRF proofs are generated by every selected committee member every
  round — not by a block producer in a batch, not periodically as in state proof certificates.
  The prover is a validator node with a per-round time budget. STARK provers and lattice SNARK
  provers are currently compute-intensive; proof generation cost is a first-class constraint
  for VRF proof compression in a way it is not for offline signature aggregation.

- *Uniqueness is non-negotiable.* For signature aggregation, the ZK proof only needs to
  attest validity — any valid proof suffices. For a VRF, the output itself must be unique:
  the same `(sk, message)` must always produce the same output. An outer ZK proof system that
  introduces its own probabilistic non-uniqueness at the proof layer could create a new avenue
  for rank grinding, even if the inner VRF is deterministic. The outer proof system must
  preserve — not undermine — the VRF's uniqueness guarantee.

- *Anonymity changes the algebraic statement.* For standard signature aggregation, the
  statement is "these signatures are valid under these public keys." For Ring VRF, the
  statement is "some key in this set produced this output, and I will not tell you which one."
  That is a set membership proof — a different circuit with different ZK requirements. It
  cannot be built by reusing a signature aggregation proof system.

- *Domain alignment determines efficiency.* Hash-based VRF (XM-VRF) → STARK is coherent:
  the VRF output and the outer compression layer share the same security assumption (hash
  collision resistance). Lattice VRF (LaV) → lattice SNARK is coherent: both rely on lattice
  hardness. Cross-domain combinations — lattice VRF compressed with a STARK, or hash VRF
  compressed with a lattice SNARK — are possible but lose the simplicity of a unified
  assumption and increase proof generation complexity for no gain.

**Lattice-based VRF — open weak points.** A future lattice-based VRF (particularly LaV-based
with optional Ring VRF anonymity) is worth pursuing once the following are resolved. Several
properties are already satisfied by LaV specifically and are not blockers:

*Already resolved by LaV:* determinism (lattice PRF is deterministic), uniqueness (PRF
evaluation, not norm-bounded signature), statefulness (standard key pair, no XMSS-style leaf
counter), multiple evaluations per key (unlimited).

*Still open:*

| Weak point | What is needed | Rough timeline |
|---|---|---|
| Proof size (~10 KB for LaV) | Sub-1 KB via improved lattice ZKP systems (LANES+ successor) | 5–10 years |
| Key size (~5.81 KB for LaV) | Under AVM's 4,096-byte stack limit, or box-native opcode design | Follows proof size |
| AVM verification opcode cost | Native `pq_vrf_verify` opcode (single C call, like current `vrf_verify`) | 2–5 years once proof size solved |
| Proof compression latency (STARK/lattice SNARK) | If outer ZK compression layer is added: under ~1 second per selected member per round; hash VRF → STARK, lattice VRF → lattice SNARK; domain must match VRF type; requires hardware acceleration for per-round production use | 5–10 years |
| Ring VRF linear scaling | Sublinear one-out-of-many proofs — polylog(N) proof size for anonymity | 3–7 years |
| QROM security | Formal security proof in the quantum random oracle model; explicitly open in literature | Unknown |
| Standardisation | IETF specification equivalent to RFC 9381; follows technical readiness | Last step |

The critical dependency chain: proof size must be solved first, which unblocks native opcode
design, which unblocks AVM integration, which unblocks standardisation. QROM security and
sublinear Ring VRF are parallel tracks that strengthen the final solution but do not block
a first lattice VRF deployment. A longer-term hybrid construction — using a lattice PRF for
the VRF output (security from LWE hardness) wrapped by a hash-based STARK for proof
compactness (two independent post-quantum security assumptions) — is theoretically attractive
but adds proof generation latency and verification cost that make it impractical until
hardware-accelerated STARK provers are widely available at the node level.

---

## The "Do Not Disturb a Sleeping Falcon" Attack

Two distinct senses of "more signatures weakening a scheme" are worth separating before
describing this attack:

- **Lattice cryptanalysis** — best known attacks against Falcon target the NTRU lattice structure
  from the public key directly and do not improve with more observed signatures. Signing more
  messages exposes no more of the key to an attacker in either randomized Falcon or FALCON-DET1024.
- **FP discrepancy attack (FALCON-DET1024 only)** — this is not a lattice attack. It requires
  signing the *same message twice* under *different floating-point conditions*. More same-message
  signing pairs increase the probability of hitting a discrepancy event — but only when the FP
  divergence condition is present. Two calls under identical FP conditions produce the same
  deterministic output with no attack surface. For randomized Falcon and FN-DSA, this attack
  surface does not exist: each call draws a fresh salt so the sampler is never called twice on
  the same input regardless of how many signatures are produced.

Paper 2024/1709 (Lin, Tibouchi, Yu, Zhang) identified a practical attack directly relevant
to the deterministic variant:

> *"When called twice on the same input with small floating-point discrepancies, the Falcon sampler
> has a small but significant chance of outputting two different lattice points with a very
> structured difference that immediately reveals the secret key."*

**The attack trigger:**

The sampler must be called **twice on the same input** with different floating-point errors. The
vulnerability arises from a discontinuity in Falcon's `SamplerZ` around near-integer center
values: a tiny FP error ε can flip `floor(c)`, and by Lemma 1 of the paper, when `floor(c)`
flips, the sampler executions are **guaranteed** to be inconsistent.

Near-integer centers occur with non-negligible probability at six positions during
`ffSampling` — the three outermost and three innermost calls to `SamplerZ` in the recursion
tree (k = 0, 1, 2 and k = n−3, n−2, n−1). These are the same six positions the countermeasure
must address (Section 7.1 of the paper). Probability is highest at the outermost pair: between
1/10,000 and 1/20,000, derived from the NTRU key structure (denominator q ≈ 12,289 for k = 0,
denominator ‖(g,−f)‖² for k = n−1); the four middle positions carry progressively smaller but
still non-negligible probabilities. All other positions have denominators exceeding
double-precision floating-point range, making integer centers undetectable in practice.

A discrepancy at the **last two** calls introduces a structured difference in just two components
of the output — specifically, `∆z0 = a + b·x^{n/2}` where a and b each range over at most 38
values ({-18,...,19}). Key recovery requires exhaustive search over at most 38² = 1,444 pairs —
less than 2^11 operations, essentially instant. A discrepancy at the **first two** calls produces
a short NTRU lattice vector — not currently believed to enable key recovery.

Three distinct probabilities describe the vulnerability:

- **Near-integer center probability** — 1/10,000–1/20,000 per signing operation (Heuristic 1,
  Section 4.3 of the paper): the probability of being in the vulnerable state on any given call.
- **Exploitable discrepancy rate** — ~1/36,000–1/45,000 per signing pair for `fpemu_det_1024`
  (from Table 2 A-values: 221–276 exploitable pairs per 10 million sign_dyn + sign_tree pairs).
- **Key recovery rate** — "around one in every 10,000 or so pairs" (paper's own words, Section
  6.1), confirmed by Table 3: `fpemu_det_1024` with 10,000 query pairs → 50% key recovery
  probability; 100,000 query pairs → 90% key recovery probability.

The paper formally characterises the attack as violating **unforgeability under chosen-message
attacks** (EUF-CMA) — a complete break of the standard security definition, not merely a practical concern.

**Why FN-DSA is not vulnerable — the precise reason:**

The paper states explicitly: *"For normal Falcon signatures, this should never happen, owing to
the use of a salt that never repeats."* With a fresh random salt on every signing call, the
sampler is **never called twice on the same input**, regardless of any FP discrepancies present.
The randomness makes the attack condition structurally impossible — not merely unlikely.

It is worth noting that the Falcon specification itself (Section 2.5.2) concluded the opposite:
after measuring FP precision at 53 vs 200 bits and finding `(δc + δσ) ≤ 2⁻⁴⁰`, the spec
declared the possibility of signature leakage *"a purely theoretic threat."* Paper 2024/1709
directly contradicted this five years later — demonstrating that the threat is concrete and
exploitable, and specifically so for deterministic variants where the same sampler input recurs.

**Why FALCON-DET1024 is vulnerable — and FPEMU is not sufficient:**

In FALCON-DET1024, standard Falcon's 40-byte random nonce is removed entirely from the
signature and replaced with a single version byte. Internally, a fixed 40-byte salt
`r = version || ℓ || "FALCON_DET" || 0x00...00` is constructed and used during hashing, but
it is never included in the output — only the 1-byte version field appears in the signature
(reflected directly in the size formula: `FALCON_SIG_COMPRESSED_MAXSIZE - 40 + 1`). The random
tape for the sampler is derived deterministically as `SHAKE(ℓ || sk || msg)` rather than from
an external RNG. Signing the same message twice with the same key therefore produces the
identical sampler input every time.

The FALCON-DET1024 codebase acknowledges the FP risk: only `fpemu_det` (integer-emulated FP) is
the supported variant; `avx2_det`, `avx2_fma_det` and similar are present in the codebase but
explicitly unsupported and warned against in the README due to floating-point discrepancy risks.
The "Do Not Disturb" paper then identifies three concrete sources of FP discrepancy that can
trigger the attack even under the recommended configuration:

1. **IEEE-754 weak determinism** — even the same source code, compiler, and options can produce
   different results due to extended precision in x87 FPU registers. The paper notes this as a
   known source but does not explore it further experimentally.

2. **`sign_dyn` vs `sign_tree` API variants within the same FPEMU-enabled binary** — these two
   signing APIs accept different key formats: `sign_tree` takes a precomputed Falcon tree as
   input while `sign_dyn` generates it on the fly. Triggering the vulnerability therefore requires
   an application that explicitly supports both signing modes. Despite this, they compute the same
   floating-point operations in a subtly different order at the deepest recursive layer (n=4). The `t1` component of the `split_fft` operation is evaluated
   as `(1/2) × ((1/√2 × diff_a) − (−1/√2 × diff_b))` in `sign_dyn` and as
   `(1/(2√2)) × (diff_a + diff_b)` in `sign_tree` — mathematically equivalent, but not in
   IEEE-754 because FP arithmetic is not distributive. The resulting center discrepancy is passed
   to `SamplerZ`, where a near-integer input triggers the floor discontinuity. Crucially,
   **only centers are affected, not standard deviations** — consistent with Lemma 2 of the paper
   proving σ errors are non-dangerous. This occurs **even in `fpemu_det`**. Importantly, over
   70% of discrepancies from this source occur at the **last two** SamplerZ calls, directly
   enabling key recovery. Experimental results (Table 2, 10 million queries per instance):
   `fpemu_det_1024` produces 221–276 exploitable pairs per 10 million sign_dyn + sign_tree pairs.

3. **FMA-optimized code vs non-FMA variants** — fused multiply-add instructions cause
   discrepancies between `avx2_fma_det` and other variants. Importantly, the paper found **no
   discrepancies** between `fpemu_det`, `fpnative_det`, and `avx2_det` (non-FMA) when using the
   same signing mode — native floats without FMA match fpemu exactly. FMA discrepancies differ
   from the dynamic/tree case in one key respect: they tend to hit the **first two** SamplerZ
   calls more than the last two (Section 6.2), making them less directly exploitable for key
   recovery per discrepancy than the dynamic/tree source. Total discrepancy counts are higher
   (Table 4 shows ~700–1,100 total pairs per 10M vs ~280–340 for dynamic/tree) but the
   last-two-call fraction is lower. Key recovery rates across both sources are experimentally
   similar (Tables 3 and 5).

   This FMA discrepancy was independently observed on ARMv8 hardware as early as 2022:
   Nguyen and Gaj (*Fast Falcon Signature Generation and Verification Using ARMv8 NEON
   Instructions*, NIST PQC Conference 2022) measured 7,000 out of 100,000 outputs of
   `fpr_expm_p63` differing between FMA and non-FMA code on both Apple M1 and Cortex-A72,
   and disabled FMA by default in their implementation for this reason. Paper 2024/1709
   later formalised this as a concrete key-recovery attack.

The FALCON-DET1024 authors correctly identified the unsupported FP variants as dangerous and
warned against them. The paper demonstrates that they missed a vulnerability in the configuration
they considered safe: using both signing APIs with the same key is sufficient to trigger key
recovery, even with integer FP emulation enabled.

**Implementation note:** The `deterministic.c` wrapper in the Algorand FALCON-DET1024 codebase
exclusively calls `falcon_sign_dyn_finish` — it never invokes `sign_tree`. The sign_dyn/sign_tree
discrepancy is therefore only reachable in practice if a caller bypasses the wrapper and calls
the underlying Falcon library's `sign_tree` directly with the same key. Within normal use of the
`falcon_det1024_sign_compressed` API the vulnerability path does not exist. The risk arises only
if the key is shared between the deterministic wrapper and direct calls to the base Falcon library.

**The blockchain passive scan scenario:**

The paper explicitly calls out the blockchain context: *"an adversary can passively scan the
blockchain, waiting for a discrepancy to appear, and skim off the corresponding private key when
it happens"* — directly analogous to how Bitcoin nonce-reuse attacks were carried out passively
on the blockchain. For Algorand, any deployment of FALCON-DET1024 where the same key signs the
same message twice under different floating-point conditions — across different nodes, API paths,
or software versions — exposes the private key with no active intervention needed by the attacker.

The spec's own warning ("the same private key should not be used to sign the same message digest
using functionally inequivalent sampling procedures") anticipated this class. The paper demonstrated
it concretely in 2025, including the case the spec considered the safe configuration. Mitaka and
Antrag — other lattice schemes using the same `SamplerZ` — are **not** vulnerable because their
sampler is never called with near-integer centers; Falcon's key structure is what makes it
uniquely sensitive.

**Proposed countermeasure (Section 7.1 of the paper):**

The paper proposes two changes that together eliminate the vulnerability:

1. Replace `SamplerZ` with `NewSamplerZ` — uses `⌊c⌉` (round to nearest integer) instead of
   `⌊c⌋` (floor). This shifts the instability from integer centers to half-integer centers.
2. Restrict key generation so that `‖(g,−f)‖²` is odd — this ensures half-integer centers
   cannot appear at the six vulnerable positions in the Falcon tree traversal.

**The critical issue for existing FALCON-DET1024 keys:**

The Falcon C reference implementation — the basis of FALCON-DET1024 — **always generates keys
with `‖(g,−f)‖²` even**, due to an implementation shortcut in the extended GCD algorithm. This
means **existing FALCON-DET1024 keys cannot benefit from this countermeasure**. Applying the fix
requires both a modified key generation algorithm (to produce odd `‖(g,−f)‖²`) and the new
signing algorithm (`NewSamplerZ`). All keys generated by the current C implementation are
disqualified from the countermeasure without re-keying.

**Fixing the dynamic/tree discrepancy is simpler (Section 7.2):**

The dynamic/tree API discrepancy can be eliminated by a targeted change of just a few lines of C
in `sign_tree`'s bottom recursion layer (n=4), reordering the FP operations to match `sign_dyn`.
Alternatively, the code base already contains a simpler n=2 bottom layer that doesn't have the
re-ordering issue, or an even simpler n=1 bottom layer that exists in commented-out form —
skipping to either eliminates the discrepancy with no change to Falcon's cryptographic operations.
Testing with 10 million sign_dyn/sign_tree pairs after either fix: zero discrepancies, no
measurable performance impact. This fix does not address the FMA discrepancy; for full protection,
FPEMU should also be consistently enforced.

**Acknowledgement — Peikert and Pornin both consulted:**

Paper 2024/1709's acknowledgements state: *"We would like to thank Chris Peikert and Thomas Pornin for
useful comments and discussions on a previous version of this paper."* Both the co-designer of
FALCON-DET1024 (Peikert) and Falcon's principal author and `rust-fn-dsa` implementor (Pornin)
are aware of the paper's findings.

---

## Key Gaps in Falcon-DET1024

Figure 1 of the Paper 2024/1769 shows the two signing procedures side by side:

```
Sgn (standard Falcon)            Sgn+ (Falcon+ / FN-DSA)
01 Sample salt r                 06 repeat
02 repeat                        07 Sample salt r
03 s ← f⁻¹(H(r, m))              08 s ← f⁻¹(H(pk, r, m))
04 until ‖s‖₂ ≤ β                09 until ‖s‖₂ ≤ β
05 σ := (r, s)                   10 σ := (r, s)
```

Falcon-DET1024 has **neither** modification: no random salt and no public key binding.
It is further from the proven framework than even standard unmodified Falcon.

| Gap | Explanation |
|---|---|
| No formal security proof | GPV proof fails; Falcon+ proof does not cover the deterministic variant. This was a known, deliberate tradeoff by Peikert (co-author of GPV itself) — the spec is honest about it. The gap became more pressing once the Paper 2024/1769 formalised it and proved the randomised variant secure |
| No public key binding | Multi-user security loss of ~20 bits at Algorand's account scale; completely absent from the spec |
| Salt absent (not just outside the loop) | Conditional distribution problem unresolvable without randomness |
| Fixed-size limited to CT format (1538 bytes) | Padded format (1280 bytes) is impossible: it loops until the compressed signature fits, retrying with a new random nonce — with a deterministic nonce there is nothing to retry with, the same call produces the identical output. CT format (1538 bytes) IS achievable and fully implemented: sign in compressed format, then post-hoc re-encode the coefficient vector via `falcon_det1024_convert_compressed_to_ct()` — no re-signing, no private key access, pure format conversion. This is the path used for SNARK coefficient extraction (`s2_coeffs()` accepts CT only). The cost is size: CT at 1538 bytes vs padded at 1280 bytes vs compressed average ~1222 bytes. |
| FP attack surface | "Do Not Disturb a Sleeping Falcon" (Paper 2024/1709): signing the same message twice under different FP conditions exposes the private key via a structured sampler output difference. Near-integer center probability: 1/10,000–1/20,000 per call; key recovery rate: ~1 in 10,000 signing pairs (Section 6.1); 50% recovery probability at 10,000 query pairs (Table 3) |
| FPEMU does not fully protect | The "dynamic" vs "tree" API signing variants in the same FPEMU-enabled binary can produce exploitable discrepancies — FPEMU is necessary but not sufficient. A countermeasure exists (NewSamplerZ + odd key constraint) but requires re-keying: the C library always generates keys with `‖(g,−f)‖²` even, disqualifying all existing keys. Note: the Algorand `deterministic.c` wrapper calls only `sign_dyn`, so this specific discrepancy requires bypassing the wrapper and calling `sign_tree` directly from the underlying Falcon library with the same key |
| C-only reference implementation | Libc linkage required; no other pure implementation exists for FALCON-DET1024 |
| Custom non-standard variant | No hardware acceleration specific to FALCON-DET1024, no ecosystem tooling, no multi-language library support. Note: standard Falcon does have emerging FPGA implementations (e.g. Schmid et al., 2023 — first full FPGA signing and key generation on UltraScale+); the deterministic variant has none |
| QROM security unproven | The abstract GPV framework has a QROM proof via [BDF+11], cited as an advantage in the Falcon specification. However, Falcon's concrete instantiation — FFO sampler, Rényi divergence arguments, salt-inside-loop, pk binding — introduces enough technical complexity that BDF+11 does not transfer directly. Paper 2024/1769 proves Falcon+ secure in the ROM but explicitly leaves QROM as an open problem: *"we leave as an open problem a proof in the quantum random oracle model (QROM), which could likely be achieved using the techniques from [BBD+23, FFH25], provided that the Rényi arguments can be handled correctly."* This gap applies equally to FALCON-DET1024 |

---

## Use-Case Differentiated View

| Protocol component | Variant | Reason |
|---|---|---|
| Transaction signing | FN-DSA/1024 | No SNARK constraint, no RNG constraint in Algorand's architecture (off-chain signing, AVM verification-only); all FN-DSA advantages apply cleanly — formal proof, pk binding, fixed signatures, no "Do Not Disturb" exposure, NIST standard |
| State proof signing | FALCON-DET1024 | Two-condition SNARK requirement: shared digest across all signers requires both no random salt and no public key binding — structurally incompatible with FN-DSA; no configuration of FN-DSA achieves this without abandoning core security properties |
| Ephemeral consensus keys | Either (Qs≈1, security loss argument collapses) | Operational preference |
| VRF / cryptographic sortition | Neither directly — hash-based candidates emerging | Of the five VRF criteria, FALCON-DET1024 meets verifiability and determinism only; FN-DSA meets verifiability only. Both fail uniqueness and pseudorandomness — Paper 2024/1769 proves EUF-CMA for FN-DSA, not VRF pseudorandomness, which is a distinct property. Lattice-based VRF candidates (Esgin et al. LB-VRF) face a separate structural limit of one output per key pair. Hash-based constructions (XM-VRF, IACR ePrint 2026/052) satisfy all five criteria with ~5–6 KB proofs and 2^80 outputs per key pair, but are not yet standardised or production-ready |

---

## Verdict

The comparison resolves into four distinct conclusions, each applying to a different protocol
component. No single scheme wins universally; the right answer depends on what the component
actually requires.

---

**1. FALCON-DET1024 is the superior choice wherever ZK proof aggregation is involved.**

Determinism is the decisive property here. For State Proofs, FALCON-DET1024 has a structural
advantage FN-DSA cannot replicate without abandoning core security properties: achieving a
single shared digest across all signers — which lifts hashing entirely outside the ZK circuit
— requires both no random salt and no public key binding simultaneously. FN-DSA satisfies
neither condition. This is not a marginal efficiency difference; it is a design incompatibility.

The same advantage extends, in softer form, to any future ZK proof aggregation at the
transaction layer. The circuit statement for a FALCON-DET1024 signature requires no private
witness for the syndrome — `H(fixed_salt, m)` is computable from public inputs alone. FN-DSA's
`H(pk, r, m)` requires the random salt `r` as a per-instance private witness, adding
constraints that compound across N aggregated signatures. This holds regardless of whether
the outer proof system is a STARK, a lattice SNARK, or any other quantum-safe proving
architecture — the advantage is algebraic, not tied to a specific proof system.

For this class of use cases — State Proofs today, ZK-based transaction aggregation in the
future — FALCON-DET1024 is the correct choice and FN-DSA is not a viable substitute.

---

**2. FN-DSA is technically stronger for transaction signing, but the gap is unlikely to
justify a migration away from FALCON-DET1024 in practice.**

FN-DSA's advantages over FALCON-DET1024 for transaction signing are real: a formal security
proof in the ROM, public key binding closing the ~20-bit multi-user security gap, fixed-size
signatures, BUFF security properties, and NIST standardisation. In Algorand's specific
architecture — off-chain signing, AVM verification-only, server-class validator hardware —
none of the operational constraints that motivated FALCON-DET1024's design (RNG availability,
deterministic VM environments) apply on the transaction signing path. FN-DSA is the cleaner
scheme on the security dimension.

The practical question is whether these advantages are meaningful enough to justify replacing
an already-deployed, production-proven scheme. For each known weakness of FALCON-DET1024,
Algorand's deployment context substantially reduces the exploitability:

- *FP attack ("Do Not Disturb a Sleeping Falcon")*: requires an adversary to observe the
  same key signing the same message twice under two different floating-point environments.
  Algorand's `deterministic.c` wrapper restricts the library to `sign_dyn` only — triggering
  the `sign_dyn` vs `sign_tree` discrepancy requires bypassing the wrapper entirely and
  calling the underlying Falcon library directly. No adversary observing normal Algorand
  transactions has the ability to induce this condition.

- *Multi-user security loss (~20 bits)*: real but marginal. The loss manifests as a reduction
  in the work required to find a forgery across a large set of public keys simultaneously.
  At Algorand's scale this is a theoretical concern, not a demonstrated attack path.

- *No formal proof*: the scheme was deliberately scoped for the State Proof use case, where
  the SNARK constraint made the tradeoff explicit and known. The absence of a proof is a gap,
  not an active vulnerability.

If FALCON-DET1024 were not already deployed, FN-DSA would be the stronger starting point for
transaction signing. Given that it is deployed and the known weaknesses are not exploitable
through the normal signing path, migrating to FN-DSA for transaction signing is a defensible
security improvement but not a compelling necessity. The effort is better spent on the
components where the scheme choice is genuinely undecided.

One timing note: FN-DSA has not been fully finalised as FIPS 206. Production deployment
should not precede NIST finalisation regardless of scheme preference.

---

**3. VRF sortition requires a different answer at different time horizons.**

Neither Falcon variant is a viable VRF. Both fail uniqueness — the property that prevents a
validator from enumerating alternative proofs for a more favourable committee weight. The VRF
question is separate from the Falcon vs FN-DSA question and requires dedicated PQ VRF
constructions.

*Near-term (now to ~5 years):* hash-based VRF is the practical choice. Hash-based
constructions such as XM-VRF (IACR ePrint 2026/052) satisfy all five VRF criteria, produce
proofs of ~1.9–5.5 KB (or even lower), and can be verified using existing AVM hash primitives
— no new arithmetic opcodes required. Critically, a hash-based VRF does not expand the consensus
trust surface: Algorand's protocol already assumes hash collision resistance throughout, so adding
a hash-based VRF introduces no new hardness assumption to the sortition layer. Lattice-based
alternatives require SIS/LWE hardness as an additional assumption specifically in the
consensus hot path — a less conservative position for the most sensitive protocol component.

*Long-term (~10 years):* a lattice-based Ring VRF (LaV-based, IACR ePrint 2026/772) becomes
the more compelling destination — not primarily for smaller proof sizes, but because it
addresses an identity exposure property hash-based VRFs inherit from the current ECVRF:
broadcasting a proof reveals which committee member was selected. Algorand's design
substantially mitigates this in practice — self-selection means revelation and action are
simultaneous, and sub-3-second finality leaves no practical interference window. Ring VRFs
eliminate the exposure entirely, proving eligibility without revealing identity. LaV also
eliminates the statefulness constraint (no XMSS-style leaf counter, standard key pair,
unlimited evaluations). The blocker is proof size scaling linearly with committee size; this
requires sublinear one-out-of-many proofs, which are an open research problem on a roughly
10-year horizon given hardware and algorithmic progress.

The path is: deploy hash-based PQ VRF now, upgrade to sublinear Ring VRF when it matures.

---

**4. Everything else is best addressed through the opcode-first framework.**

For use cases beyond State Proofs, transaction signing, and VRF sortition — multisig
variants, application-specific signing, experimental schemes — the right mechanism is a
staged opcode approach rather than immediate protocol enshrinement:

- *Opcode stage*: add `<pq-dsa>_verify` when a scheme reaches maturity, meaningful adoption,
  and KMS/hardware support. The `ecdsa_verify` opcode is the existing precedent — in
  production for EVM-compatible accounts without ever being promoted to a native account type,
  demonstrating the opcode stage is sufficient for real deployment.

- *Native promotion*: promote to a 1st-class protocol account type only when (a) the
  delegated LSig capability gap becomes a real operational constraint, (b) protocol-level
  multisig is needed and ARC-based convention is insufficient, and (c) the scheme passes
  Algorand's affinity criteria — throughput-compatible, latency-compatible, optimal for
  Algorand's specific constraints rather than generically mature. Hash-based PQ DSA schemes,
  for example, may reach the opcode stage but would not pass the native promotion threshold
  on throughput grounds; multi-kilobyte per-transaction proofs are incompatible with
  Algorand's performance envelope in a way they are not for Bitcoin's store-of-value use case.

- *Hybrid multisig during transition*: native multisig extended to support mixed schemes
  should require both an Ed25519 and a Falcon signature in a 2-of-2, so an attacker must
  break both to gain control. This gives defence-in-depth during the migration window and
  should be treated as a protocol design goal rather than an optional enhancement.

- *Experimental and high-risk schemes*: multivariate schemes recently advanced in the NIST
  onramp process offer very small signatures and public keys but carry higher security
  uncertainty. These should remain at the opcode stage until their security properties are
  more thoroughly established. The opcode model is precisely the right mechanism for this:
  developers can use them in production applications, the ecosystem develops experience, and
  no protocol-level commitment is made until the scheme is sufficiently understood.

---

**The two-family conclusion.**

Algorand's full PQ migration requires both cryptographic families, serving different protocol
components with genuinely different requirements. FALCON (lattice-based) is the right native
scheme for transaction signing and state proofs: determinism, ZK aggregation compatibility,
throughput-compatible signature and key sizes, and three years of production deployment.
A hash-based scheme is the right path for VRF sortition: no new hardness assumption in the
consensus hot path, existing AVM hash opcode compatibility, and near-term practical
deployability. Neither family substitutes for the other. A `falcon_verify` opcode or native
Falcon account type addresses one part of Algorand's PQ migration; a `pq_vrf_verify` opcode
for a hash-based scheme addresses a separate and equally necessary part.

---

## References

- Algorand ABFT Specification, Section 3 — Identity, Authorization, and Authentication (release 7791a63):
  https://github.com/algorandfoundation/specs/releases/tag/7791a63
- Micali, Reyzin, Vlachos, Wahby, Zeldovich — *Compact Certificates of Collective Knowledge*,
  IACR ePrint 2020/1568.
  Short URL: https://ia.cr/2020/1568
- Fouque (Université de Rennes, IUF), Gajland (IBM Research Zurich), de Groote (ENS Paris-Saclay),
  Janneck (Ruhr University Bochum), Kiltz (Ruhr University Bochum) —
  *A Closer Look at Falcon*, in *Advances in Cryptology – EUROCRYPT 2026*, Lecture Notes in
  Computer Science, Springer, May 2026. IACR ePrint 2024/1769 (received 2024-10-30, last revised 2026-03-02).
  Short URL: https://ia.cr/2024/1769
- Lin, Tibouchi, Yu, Zhang — *Do Not Disturb a Sleeping Falcon: Floating-Point Error Sensitivity
  of the Falcon Sampler and Its Consequences*, IACR ePrint 2024/1709, EUROCRYPT 2025.
  Acknowledged by both Chris Peikert (FALCON-DET1024 author) and Thomas Pornin (Falcon
  principal author) prior to publication.
  Short URL: https://ia.cr/2024/1709
- Düzlü, Fiedler, Fischlin — *BUFFing FALCON without Increasing the Signature Size*,
  IACR ePrint 2024/710.
  Short URL: https://ia.cr/2024/710
- Fouque, Hoffstein, Kirchner, Lyubashevsky, Pornin, Prest, Ricosset, Seiler, Whyte, Zhang —
  *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU*, Specification v1.2, 2020.
  https://falcon-sign.info
- Lazar, Peikert — *Deterministic Falcon-1024*, `falcon-det.pdf`, Algorand Inc., November 2021:
  https://github.com/algorand/falcon/blob/main/falcon-det.pdf
- Algorand Foundation — *Algorand Post-Quantum Ledger: Securing the ledger, one account type
  at a time*, May 2026.
  https://algorand.co/blog/algorand-post-quantum-ledger
- Pornin — `rust-fn-dsa` (2025): https://github.com/pornin/rust-fn-dsa
- Pornin — RFC 6979, *Deterministic Usage of DSA and ECDSA*, 2013
- NIST — *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)*, August 2024.
  https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- NIST — *FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)*, August 2024.
  https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf
- Nguyen, Gaj — *Fast Falcon Signature Generation and Verification Using ARMv8 NEON Instructions*,
  4th NIST PQC Standardization Conference, 2022.
  https://csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/fast-falcon-signature-generation-and-verification-pqc2022.pdf
- Mattsson, Perlner, Pornin, Lyubashevsky et al. — *NIST PQC Forum: FN-DSA discussion thread
  (hedged signing, security levels, message recovery)*, October–November 2025.
  https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y
- Cremers, Düzlü, Fiedler, Fischlin, Janson — *BUFFing Signature Schemes Beyond Unforgeability
  and the Case of Post-Quantum Signatures*, IACR ePrint 2020/1525.
  Short URL: https://ia.cr/2020/1525
- Aardal, Aranha, Boudgoust, Kolby, Takahashi — *Aggregating Falcon Signatures with LaBRADOR*,
  CRYPTO 2024. IACR ePrint 2024/311.
  Short URL: https://ia.cr/2024/311
- Turner — *Use of the FN-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)*,
  IETF Internet-Draft draft-turner-lamps-cms-fn-dsa-00.
  https://www.ietf.org/archive/id/draft-turner-lamps-cms-fn-dsa-00.txt
- Li, Tan, Szalachowski, Sharma, Zhou — *Post-Quantum VRF and its Applications in Future-Proof
  Blockchain System*, arXiv 2109.02012, 2021. https://arxiv.org/abs/2109.02012
- Xu, Esgin, Steinfeld — *Lattice-based Ring Verifiable Random Functions*, IACR ePrint 2026/772.
  Short URL: https://ia.cr/2026/772
- Ghosh, Dutta, Mukhopadhyay — *Key Updatable Hash Based VRF*, IACR ePrint 2026/052
  (received 2026-01-13, last revised 2026-02-27).
  Short URL: https://ia.cr/2026/052
- Goldberg, Reyzin, Papadopoulos, Vcelak — *Verifiable Random Functions (VRFs)*,
  IETF Internet-Draft draft-irtf-cfrg-vrf-03 (Algorand's implementation basis).
  https://www.ietf.org/archive/id/draft-irtf-cfrg-vrf-03.txt
- Goldberg, Reyzin, Papadopoulos, Vcelak — *Verifiable Random Functions (VRFs)*,
  RFC 9381, IRTF, August 2023 (finalized standard).
  https://www.rfc-editor.org/rfc/rfc9381
- Algorand libsodium fork — *ECVRF-ED25519-SHA512-Elligator2 implementation*, ietfdraft03.
  https://github.com/algorand/libsodium/tree/004952bb57b2a6d2c033969820c80255e8362615/src/libsodium/crypto_vrf/ietfdraft03

