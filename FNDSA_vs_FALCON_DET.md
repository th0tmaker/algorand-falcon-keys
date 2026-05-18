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

## Context

This document compares two post-quantum signature schemes:

- **FALCON-DET1024** — the deterministic Falcon variant specified by Lazar and Peikert (Algorand
  Inc., November 2021) in [`falcon-det.pdf`](https://github.com/algorand/falcon/blob/main/falcon-det.pdf),
  currently used in Algorand's state proofs and exposed as an AVM opcode.

- **FN-DSA** — the forthcoming NIST standard (FIPS 206), based on Falcon with conservative modifications
  that enable a formal security proof.

**The comparison covers security, protocol fit, practical migration implications, and open questions
raised in community discussion.**

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

> **On Paper 2024/1769:** Throughout this document, "Paper 2024/1769" refers to IACR ePrint
> 2024/1769, *"A Closer Look at Falcon"* (Fouque, Gajland, de Groote, Janneck, Kiltz) — first
> received October 2024, last revised March 2, 2026, published in *Advances in Cryptology –
> EUROCRYPT 2026* (Springer LNCS), May 2026.
> Short URL: https://ia.cr/2024/1769

> **On Paper 2024/1709:** Throughout this document, "Paper 2024/1709" refers to IACR ePrint
> 2024/1709, *"Do Not Disturb a Sleeping Falcon: Floating-Point Error Sensitivity of the Falcon
> Sampler and Its Consequences"* (Lin, Tibouchi, Yu, Zhang) — published at the EUROCRYPT 2025
> conference. Short URL: https://ia.cr/2024/1709

> **On Paper 2024/710:** Throughout this document, "Paper 2024/710" refers to IACR ePrint
> 2024/710, *"BUFFing FALCON without Increasing the Signature Size"* (Düzlü, Fiedler, Fischlin).
> Short URL: https://ia.cr/2024/710

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
concrete exploitable attacks: no known attack on Falcon-512 improves with more observed signatures.
The Rényi divergence loss is an artifact of the security reduction, not an adversarial capability.

The real concern for long-lived Falcon-512 keys is different: the thin ISIS baseline leaves almost
no room for future algorithmic improvements. Lattice cryptanalysis has historically advanced, and a
7-bit improvement would push Falcon-512 below the security target. Falcon-1024's ~279-bit baseline
provides a 23-bit buffer above its 256-bit target — a substantially more comfortable cushion against
future progress.

For **ephemeral keys** (one-time use, then discarded), Falcon-512 might be appropriate: signing
query concerns are irrelevant and the size savings (666 vs 1280-byte signatures, 897 vs 1793-byte
public keys) are meaningful. For **persistent keys**, Falcon-512 is likely safe against current
known attacks but carries a thinner margin against future cryptanalytic improvements than the 1024
parameter set. Whether that margin is acceptable is a security-policy judgement, not a settled fact.

---

## FN-DSA Advantages

### Security

- **Formal security proof** — FN-DSA is proven secure in the random oracle model (Paper 2024/1769).
  The proof establishes that breaking FN-DSA is *equivalent* to solving t-R-ISIS — necessary and
  sufficient. Any improvement in lattice cryptanalysis directly translates to an attack on FN-DSA,
  and vice versa. FALCON-DET1024 has no formal security proof.

  It is important to note that this gap was a **known and deliberate tradeoff**, not an oversight.
  Chris Peikert — one of the architects behind the GPV framework itself — co-authored `falcon-det.pdf`.
  He undoubtedly understood better than anyone what a GPV proof requires and where
  the deterministic variant deviates from it. The Falcon specification itself (Section 2.2.2)
  explicitly considered de-randomization and noted: *"While this solution can be applied in a few
  specific use cases, we do not consider it for Falcon"* — acknowledging its legitimacy for
  targeted applications while choosing hash randomization for the general scheme. FALCON-DET1024
  is precisely one of those specific use cases. The `falcon-det.pdf` spec is honest about the
  informal security reasoning and scopes the scheme to a specific use case (SNARK-friendly compact
  certificates).
  What changed is that the Paper 2024/1769 later formalised the GPV proof gap more precisely
  and provided a proof for the randomised variant — a proof that did not exist when the
  deterministic spec was written in 2021.

  A critical contribution of the paper is Rényi order optimisation. **What the Rényi argument
  does:** in any security reduction, the signatures the reduction produces while simulating honest
  signing can't be identical to real ones — it's faking them without the real trapdoor. Rényi
  divergence of order *a* between the simulated and real distributions is the formal measure of
  how close they are, and directly determines the security loss. The reduction works by
  *programming* the random oracle: for each signing query on message m, it picks a fresh salt *r*,
  chooses a syndrome `c = H(pk, r, m)` it knows how to solve, and programs H(pk, r, m) = *c* in
  its random oracle simulation. This only works if *r* is fresh and independent per query — the
  reduction needs freedom to choose *c*. The Rényi argument then bounds how much this programmed
  distribution diverges from the real one across all Q_s signing queries.

  The choice of order *a* is a mathematical trade-off: higher *a* gives a tighter bound per query
  but compounds worse over many queries. The Falcon NIST submission specification (cited as
  [PFH+22] in Paper 2024/1769) recommends *a* = 2^λ — applying this naively to Falcon-1024 would
  produce a **60-bit security loss**, leaving only ~219 bits of provable security. The paper's
  optimised parameter selection reduces the Rényi loss to **8 bits**, recovering 52 bits. Combined
  with the remaining ~15-bit loss from random oracle query overhead, the full proof delivers the
  256-bit security target (279 − 8 − 15 ≈ 256). Without this optimisation, even Falcon+ with the
  1024 parameter set would have been significantly undersecured.

  FALCON-DET1024 cannot claim these provable security numbers. Without a random salt there is no
  freedom to choose *c*, the random oracle cannot be programmed, the GPV reduction does not start,
  and there is nothing to apply the Rényi optimisation to. The 113/119-bit (Falcon+/512) and
  256-bit (Falcon+/1024) provable security figures are inaccessible to the deterministic variant
  by construction.

  How the Rényi argument applies across all three variants:

  | Variant | Random oracle programmable? | Conditional distribution clean? | Rényi optimisation applies? |
  |---|---|---|---|
  | FALCON-DET1024 | No — fixed salt gives no freedom to choose *c* | — | No — no reduction to apply it to |
  | Standard Falcon | Yes — random *r* before the loop | No — fixed *c* during loop skews distribution of *s* | No — proof doesn't go through |
  | Falcon+ / FN-DSA | Yes — fresh *r* on every loop iteration | Yes — joint rejection sampling over (r, s) | Yes — 8-bit loss, 256-bit provable security |

  FALCON-DET1024 shares the same underlying parameters as Falcon+/1024, so it starts from the
  same ~279-bit ISIS hardness baseline. This is reassuring in one sense — no known classical or
  quantum attack comes close to that hardness, and cryptanalysts attacking the ISIS problem attack
  both schemes equally. However, the ~279-bit figure is a lattice estimator result, not a theorem.
  Without a proof reduction, there is no formal guarantee that breaking FALCON-DET1024 actually
  requires solving ISIS. A proof reduction is what establishes that relationship rigorously: "if
  you can forge a signature, I can solve ISIS." Without it, the security claim rests on a
  plausibility argument rather than a mathematical equivalence. An attack exploiting the
  deterministic structure specifically — bypassing the ISIS hardness entirely — cannot be formally
  ruled out. The "Do Not Disturb" attack is exactly this kind of structural attack: it ignores the
  ~279-bit ISIS hardness completely and exploits a floating-point property unique to deterministic
  signing. The ISIS estimate says nothing about it.

- **Public key binding** — FN-DSA incorporates a hash of the public key into every signature:
  `H(hpk, r, m)` instead of `H(r, m)`. Without binding, multi-user security degrades by
  approximately log₂(N) bits where N is the number of accounts — roughly 20 bits for Algorand's
  scale. With binding, each account's security is evaluated independently at full strength. This is
  the Pornin-Stern transformation [PS05], known since 2005 and described as "standard
  cryptographic practice" and "good cryptographic engineering" in the Paper 2024/1769.

- **Salt resampling inside the rejection loop (Falcon+ modification)** — the core structural
  change enabling the formal proof; covered in detail in the Rényi section above.

- **BUFF security (Beyond UnForgeability Features)** — FN-DSA achieves three additional security
  properties on top of standard unforgeability, formalised by Cremers et al. and shown to follow
  from pk binding for FALCON by Paper 2024/710 (Düzlü, Fiedler, Fischlin):
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
  holds both mathematically (Ed25519 has native EO) and at the protocol level. A FN-DSA
  migration would hash the 1793-byte public key to derive a 32-byte address
  `H("PqAddr" || pubkey_bytes)`, and verification uses the key registered for that
  address — so the address-to-key binding still enforces which key is checked. FALCON-DET1024
  benefits from the same protocol-level mitigation.

  The meaningful difference is what happens *outside* that infrastructure. FN-DSA's
  `H(r, pk, m)` makes the signature mathematically inseparable from the specific key — a
  verifier handed only `(pk, m, σ)` can be certain no other key could have produced it.
  FALCON-DET1024's `H(fixed_salt, m)` provides no such mathematical guarantee; attribution
  relies entirely on the surrounding system having correctly associated the key with the address.
  This matters in SNARK circuits, cross-chain proofs, or any context where the Algorand address
  infrastructure is not present to enforce the binding.

- **FFO Sampler now formally proven** — The Paper 2024/1769 provides the first formal proof of
  the FFO Sampler (Corollary 1: Rényi divergence bounded by ≈ 1 + 2aε²). The sampler's Gaussian
  output was previously justified only by analogy to the Klein Sampler. Both FALCON-DET1024 and
  FN-DSA use the FFO Sampler, so both benefit from this result.

- **Proof tightness** — The hardness assumptions are necessary, not just sufficient. Breaking
  FN-DSA is equivalent to solving t-R-ISIS — an attack on either directly yields an attack on the
  other. The Rényi divergence constants remain as proof overhead, but the equivalence itself is tight.

### Signature Format

- **Fixed-size signatures** — FN-DSA/1024 produces exactly 1280-byte signatures, matching the
  `FALCON_SIG_PADDED_SIZE` defined in the Falcon specification. This padded format works
  reliably because rejections due to oversized compressed signatures can trigger a fresh nonce,
  allowing a retry. FALCON-DET1024 cannot retry and so must accept variable-length compressed
  signatures (up to 1423 bytes max).

- **Fixed size simplifies everything downstream** — buffer allocation, network framing, storage
  calculations, and block capacity planning all become deterministic when every signature is exactly
  1280 bytes.

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
  generated for different application contexts."* The maximum size is not confirmed from our
  primary sources but is almost certainly 255 bytes — FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
  both use this limit and NIST applied it consistently across all three PQC signature standards.

  This is a FIPS 206 standardisation addition — neither the original Falcon specification (v1.2)
  nor FALCON-DET1024 include a context string mechanism. Both hash only the salt and message:
  `H(r || m)` and `H(fixed_salt || m)` respectively. Any domain separation for FALCON-DET1024
  must be implemented at the application layer by the caller, which is ad hoc, not standardised,
  and easy to omit. FN-DSA builds it into the primitive, enabling explicit separation between
  transactions, state proofs, and consensus votes using the same key without collision risk.

- **Why Pornin chose non-determinism for FN-DSA** — His design history is instructive: RFC 6979 made ECDSA deterministic because ECDSA nonce reuse directly
  exposes the private key — a critical vulnerability requiring a fix. In ECDSA, the signature is
  `s = k⁻¹(hash(m) + r·d) mod n` where `k` is the random nonce, `r = (k·G).x mod n` is the
  x-coordinate of the resulting curve point, and `d` is the private key. If
  the same `k` is used for two different messages, two equations share the same unknowns and
  solving for `d` is trivial linear algebra — two signatures is all it takes. This is exactly
  what happened to the PlayStation 3 (2010, static `k`) and to Android Bitcoin wallets (2013,
  weak PRNG producing repeated `k` values). RFC 6979 fixed this by deriving `k` deterministically
  from the private key and message, making nonce reuse structurally impossible. Determinism was
  a security requirement, not a preference.

  For FN-DSA, poor randomness does not have the same catastrophic failure mode. The random salt
  `r` picks a hash target, not a nonce entering an algebraic equation alongside the private key.
  Reusing `r` for different messages produces different hash targets and does not yield a linear
  system recoverable by simple algebra. Randomness in FN-DSA is primarily a security proof
  enabler, not a vulnerability patch. Pornin's choice to implement FN-DSA non-deterministically
  reflects this different mathematical context, not an abandonment of his prior preference for
  determinism.

---

## Falcon-DET1024 Advantages

- **Already deployed** — Algorand's state proof infrastructure has used FALCON-DET1024 in production
  since 2022, and it is also exposed as an AVM opcode. Migration would require substantial testing and
  validation effort across the full protocol stack.

- **Determinism as convention** — Matches Ed25519 behaviour. Applications or tooling that
  incorrectly assumes byte-identical signatures would not break. The ABFT spec does not guarantee
  this, but such assumptions may exist in external tooling built against Algorand.

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

  - *Sublinear SNARK aggregation*: The SNARK aggregation scheme for Falcon by Aardal et al.
    achieves asymptotically sublinear aggregated signature size specifically because of
    determinism. With FN-DSA, all salts must be included in the aggregated proof, forcing linear
    scaling. Determinism eliminates the salt overhead and enables sublinear aggregation.

- **SNARK friendliness for compact certificates — the primary stated motivation** — The
  `falcon-det.pdf` spec is explicit that this is the core reason for choosing derandomization over
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
software, and dismissing it entirely is wrong. Several environments common in the blockchain
ecosystem either lack reliable OS-level entropy or make RNG access structurally difficult:

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

Migrating from Ed25519 to FN-DSA involves protocol-level changes beyond swapping the signature
algorithm. Key considerations:

### Account Address Scheme

Ed25519's 32-byte public key IS the account address. FN-DSA's 1793-byte public key cannot serve
this role directly. The address would need to be derived as a hash of the public key, following
Algorand's existing domain-separation pattern:

```
address = H("PqAddr" || pubkey_bytes)
```

This is consistent with how Algorand already derives addresses for MultiSig accounts
(`SHA512/256("MultisigAddr" || ...)`) and LogicSig accounts (`SHA512/256("Program" || bytecode)`).

For a hybrid transition period, the address could commit to both keys:

```
address = SHA512/256("HybridAddr" || ed25519_pubkey || fndsa_pubkey)
```

This enables the dual-signature approach (requiring both Ed25519 and FN-DSA) during the transition,
with the address unchanged regardless of which key is eventually retired.

### Verification Now Requires a State Read

Ed25519 verification is pure computation — the address bytes ARE the public key. FN-DSA
verification requires looking up the account's registered 1793-byte public key from on-chain state:

```
address → state read → pubkey → verify(sig, pubkey, message) → valid/invalid
```

This is a genuine protocol change with performance implications. Potential mitigations:
- **Pre-fetching**: batch all state reads for a block's transactions in parallel before the
  verification pass.
- **Key caching**: active accounts with stable FN-DSA keys have very high cache hit rates

The state read is one step removed from the current model but is a well-understood pattern.

### Block Structure: Signature Storage

FN-DSA signatures at 1280 bytes vs Ed25519 at 64 bytes represent a 20x increase per transaction.
A SegWit-style separation addresses both block capacity and long-term storage:

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
to change for FN-DSA. What changes is the storage and transmission cost of the signature bytes
themselves: 1280 bytes vs 64 bytes per transaction. The witness separation addresses that: after
Algorand's instant BA* finality, the witness section can be pruned by most nodes. The `sig_root`
persists permanently as proof that all signatures were valid. Anyone needing to verify a historical
signature requests it from an archival witness node along with a Merkle inclusion proof, verifies
the proof against the known `sig_root`, then verifies the signature against the transaction's
sender's registered pubkey.

Algorand's existing state proof infrastructure (vector commitments, Merkle trees) provides the
exact tooling this requires — it is an extension of a pattern already built into the protocol.

### Archival Storage

Archival nodes that retain the full witness section face a 20x increase in signature storage:
roughly 40 TB/year at 1,000 TPS vs ~2 TB/year today. FN-DSA-1024 signatures are a tightly
bit-packed encoding of a short lattice vector — cryptographically uniform bytes with no
exploitable patterns. Generic compression produces larger output due to overhead, and converting
to the native compressed format saves only ~8-13 bytes on average (the padded format is designed
to be near the average compressed length). 1280 bytes is effectively the floor. Practical
mitigations:
- **Time-bounded retention**: archival nodes could prune witness data beyond a threshold (e.g.,
  10 years) while `sig_root` persists forever
- **Tiered storage**: recent witness data on fast storage, historical on cold storage

### Batch Verification Loss

Ed25519 supports batch verification — verifying N signatures together via a single multi-scalar
multiplication is faster than N individual verifications. FN-DSA has no equivalent. Each signature
must be verified independently. Mitigations:
- **Parallel verification**: FN-DSA verifications are fully independent and parallelise trivially
  across CPU cores.
- **SNARK aggregation** (longer-term): a block producer verifies all FN-DSA signatures and
  generates a single SNARK proof attesting their validity. Validators verify one proof instead of
  N signatures, making per-transaction verification overhead essentially zero. Active research area;
  lattice-friendly SNARK circuits are not yet efficient enough for production but the direction is clear.

---

## Use-Case Differentiated View

| Protocol component | Variant | Reason |
|---|---|---|
| Transaction signing | FN-DSA/1024 | No SNARK constraint, no RNG constraint in Algorand's architecture (off-chain signing, AVM verification-only); all FN-DSA advantages apply cleanly — formal proof, pk binding, fixed signatures, no "Do Not Disturb" exposure, NIST standard |
| State proof signing | FALCON-DET1024 | Two-condition SNARK requirement: shared digest across all signers requires both no random salt and no public key binding — structurally incompatible with FN-DSA; no configuration of FN-DSA achieves this without abandoning core security properties |
| Ephemeral consensus keys | Either (Qs≈1, security loss argument collapses) | Operational preference |

---

## The "Do Not Disturb a Sleeping Falcon" Attack

The paper 2024/1709 (Lin, Tibouchi, Yu, Zhang) identified a practical attack directly relevant
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

FPEMU is necessary but not sufficient.

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

The paper's acknowledgements state: *"We would like to thank Chris Peikert and Thomas Pornin for
useful comments and discussions on a previous version of this paper."* Both the co-designer of
FALCON-DET1024 (Peikert) and Falcon's principal author and `rust-fn-dsa` implementor (Pornin)
reviewed the paper's findings before publication. Neither contested them. This confirms the
paper's conclusions are accepted by the original authors of both schemes.

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
| Variable-length signatures | Spec explicitly rejects padded format (1280 bytes) because the retry it requires would violate determinism |
| FP attack surface | "Do Not Disturb a Sleeping Falcon" (Paper 2024/1709): signing the same message twice under different FP conditions exposes the private key via a structured sampler output difference. Near-integer center probability: 1/10,000–1/20,000 per call; key recovery rate: ~1 in 10,000 signing pairs (Section 6.1); 50% recovery probability at 10,000 query pairs (Table 3) |
| FPEMU does not fully protect | The "dynamic" vs "tree" API signing variants in the same FPEMU-enabled binary can produce exploitable discrepancies — FPEMU is necessary but not sufficient. A countermeasure exists (NewSamplerZ + odd key constraint) but requires re-keying: the C library always generates keys with `‖(g,−f)‖²` even, disqualifying all existing keys. Note: the Algorand `deterministic.c` wrapper calls only `sign_dyn`, so this specific discrepancy requires bypassing the wrapper and calling `sign_tree` directly from the underlying Falcon library with the same key |
| C-only reference implementation | Libc linkage required; no other pure implementation exists for FALCON-DET1024 |
| Custom non-standard variant | No hardware acceleration, no ecosystem tooling, no multi-language library support |
| Determinism assumed but not required | ABFT spec never mandated it; inherited from Ed25519 convention |
| QROM security unproven | Even FN-DSA lacks a quantum random oracle model proof — an open problem noted in the Paper 2024/1769 |

---

## Verdict

Neither scheme is unconditionally superior. Each has genuine strengths and the right choice
depends on what the specific protocol component actually requires.

**Where FN-DSA is the stronger choice:**

For general-purpose transaction signing, FN-DSA holds meaningful advantages: a formal security
proof, public key binding eliminating the ~20-bit multi-user security loss, fixed-size signatures,
BUFF security properties, NIST standardisation, and no exposure to the "Do Not Disturb"
floating-point attack. In Algorand's specific architecture — off-chain signing, AVM
verification-only opcodes, server-class validator hardware — the operational concerns that
motivated FALCON-DET1024's design (RNG availability, deterministic execution environments) do
not manifest on the transaction signing path. The security properties FN-DSA provides are real
and not matched by FALCON-DET1024.

**Where FALCON-DET1024 is the stronger choice:**

For SNARK-based compact certificate state proofs, FALCON-DET1024 has a structural advantage that
FN-DSA cannot replicate without abandoning core security properties. Achieving a single shared
digest across all signers — the property that lifts hashing entirely outside the SNARK circuit —
requires both no random salt and no public key binding simultaneously. FN-DSA satisfies neither.
FALCON-DET1024's deterministic design is also a natural fit for constrained signing environments
common in the blockchain ecosystem (deterministic VMs, embedded signers, cross-device
reproducibility). Its years of production deployment in Algorand's state proof infrastructure
carry real operational weight that should not be dismissed.

**The honest split:**

| Protocol component | Stronger choice | Primary reason |
|---|---|---|
| Transaction signing | FN-DSA/1024 | Formal proof, pk binding, BUFF security, NIST standard; Algorand's architecture sidesteps the RNG and AVM concerns that motivated the deterministic design |
| State proof signing | FALCON-DET1024 | Two-condition SNARK requirement is structurally incompatible with FN-DSA; deterministic design purpose-built for exactly this use case |

The case for keeping FALCON-DET1024 for transaction signing rests on operational continuity —
already deployed, production-proven, no migration risk — which are legitimate considerations
distinct from technical merit. The case for migrating to FN-DSA for transaction signing rests
on security and standardisation arguments that are equally legitimate. Reasonable people can
weigh these differently. This document does not make that call; it attempts to lay out what
each scheme actually provides and where each is genuinely suited.

**Timing caveat:** FN-DSA has not yet been fully finalised as FIPS 206. Production deployment
should be timed with or after NIST finalisation. Building and testing against current
implementations is appropriate; shipping in production is premature until the standard lands.

---

## References

- Algorand ABFT Specification, Section 3 — Identity, Authorization, and Authentication (release 7791a63):
  https://github.com/algorandfoundation/specs/releases/tag/7791a63
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
- Pornin — `rust-fn-dsa` (2025): https://github.com/pornin/rust-fn-dsa
- Pornin — RFC 6979, *Deterministic Usage of DSA and ECDSA*, 2013

