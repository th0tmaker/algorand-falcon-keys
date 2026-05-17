# FN-DSA vs Falcon-DET1024: PQ Signing Scheme Comparison for Algorand

## Context

This document compares two post-quantum signature schemes:

- **FALCON-DET1024** — the deterministic Falcon variant specified by Lazar and Peikert (Algorand
  Inc., November 2021) in [`falcon-det.pdf`](https://github.com/algorand/falcon/blob/main/falcon-det.pdf),
  currently used in Algorand's state proofs and exposed as an AVM opcode.

- **FN-DSA** — the forthcoming NIST post-quantum signature standard (FIPS 206), based on Falcon
  with conservative modifications that enable a formal security proof (Fouque et al., EUROCRYPT 2026).

The comparison covers security, protocol fit, practical migration implications, and open questions
raised in community discussion.

The FALCON-DET1024 spec predates FN-DSA as a finalized concept — the key reference paper was
not published until 2025/2026. The tradeoffs discussed here were not fully visible when Algorand
made its initial design decision.

> **On the word "determinism":** Two distinct notions appear in this document and should not be
> confused. *Signing determinism* means the same private key and message always produce the same
> signature bytes — this is FALCON-DET1024's defining property. *Computation determinism* means
> the signing algorithm produces consistent results across different hardware and compiler
> configurations — this is the floating-point emulation (`FALCON_FPEMU`) concern. The two are
> related but separate: signing determinism requires computation determinism as a precondition,
> but computation determinism alone does not imply signing determinism. Unless stated otherwise,
> "determinism" in this document refers to signing determinism.

> **Note on "EUROCRYPT 2026":** Throughout this document, "EUROCRYPT 2026" refers to IACR ePrint
> 2024/1769, *"A Closer Look at Falcon"* (Fouque, Gajland, de Groote, Janneck, Kiltz) — first
> received October 2024, last revised March 2, 2026, published as a major revision in EUROCRYPT
> 2026. Short URL: https://ia.cr/2024/1769

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

The EUROCRYPT 2026 paper's lattice estimator (Figure 11) gives raw ISIS hardness as 2^121.2 for
n=512 and 2^279.2 for n=1024. The paper's summary table rounds these to 120 and 278; both
representations appear throughout this document. The ~279-bit hardness for n=1024 provides a
23-bit buffer above the 256-bit target, comfortably absorbing the 8-bit Rényi divergence loss.

---

## Parameter Set: 512 vs 1024

A natural question is whether Falcon-512 or FN-DSA/512 could be used to reduce key and signature
sizes. The EUROCRYPT 2026 paper gives concrete provable security numbers:

| Variant | ISIS hardness (estimator) | Qs=2^64 security | Qs=2^58 security |
|---|---|---|---|
| Falcon+-512 | ~121 bits (2^121.2) | 113 bits | 119 bits |
| Falcon+-1024 | ~279 bits (2^279.2) | 256 bits | 256 bits |

Falcon-512's ISIS hardness sits at ~121 bits — close to the NIST Level I target with little margin.
The 113/119-bit provable security figures at Qs=2^64/2^58 are **proof tightness** results, not
concrete exploitable attacks: no known attack on Falcon-512 improves with more observed signatures.
The Rényi divergence loss is an artifact of the security reduction, not an adversarial capability.

The real concern for long-lived Falcon-512 keys is different: the thin ISIS baseline leaves almost
no room for future algorithmic improvements. Lattice cryptanalysis has historically advanced, and a
7-bit improvement would push Falcon-512 below the security target. Falcon-1024's ~279-bit baseline
provides a 23-bit buffer above its 256-bit target — a substantially more comfortable cushion against
future progress.

For **ephemeral keys** (one-time use, then discarded), Falcon-512 is clearly appropriate: signing
query concerns are irrelevant and the size savings (666 vs 1280-byte signatures, 897 vs 1793-byte
public keys) are meaningful. For **persistent keys**, Falcon-512 is likely safe against current
known attacks but carries a thinner margin against future cryptanalytic improvements than the 1024
parameter set. Whether that margin is acceptable is a security-policy judgement, not a settled fact.

---

## FN-DSA Advantages

### Security

- **Formal security proof** — FN-DSA is proven secure in the random oracle model (Fouque et al.,
  EUROCRYPT 2026). The proof establishes that breaking FN-DSA is *equivalent* to solving
  t-R-ISIS — necessary and sufficient. Any improvement in lattice cryptanalysis directly translates
  to an attack on FN-DSA, and vice versa. FALCON-DET1024 has no formal security proof.

  It is important to note that this gap was a **known and deliberate tradeoff**, not an oversight.
  Chris Peikert — co-author of the original GPV framework itself (the "P" in GPV) — co-authored
  `falcon-det.pdf`. He understood better than almost anyone what a GPV proof requires and where
  the deterministic variant deviates from it. The spec is honest about the informal security
  reasoning and scopes the scheme to a specific use case (SNARK-friendly compact certificates).
  What changed is that the EUROCRYPT 2026 paper later formalised the GPV proof gap more precisely
  and provided a proof for the randomised variant — a proof that did not exist when the
  deterministic spec was written in 2021.

  A critical contribution of the paper is Rényi order optimisation. Falcon's own specification
  recommends a Rényi divergence order of a=2^λ — applying this naively to Falcon-1024 would
  produce a **60-bit security loss**, leaving only ~219 bits of provable security. The paper's
  optimised parameter selection reduces this loss to **8 bits**, recovering 52 bits and delivering
  the full 256-bit security target. Without this optimisation, even Falcon+ with the 1024 parameter
  set would have been significantly undersecured.

- **Public key binding** — FN-DSA incorporates a hash of the public key into every signature:
  `H(hpk, r, m)` instead of `H(r, m)`. Without binding, multi-user security degrades by
  approximately log₂(N) bits where N is the number of accounts — roughly 20 bits for Algorand's
  scale. With binding, each account's security is evaluated independently at full strength. This is
  the Pornin-Stern transformation, known since 2005 and described as "standard cryptographic
  engineering" in the EUROCRYPT 2026 paper.

- **Salt resampling inside the rejection loop (Falcon+ modification)** — In standard Falcon the
  random salt `r` is fixed before the rejection loop. In FN-DSA, a fresh `r` is drawn on each
  rejection. This resolves the conditional distribution problem that prevented the GPV proof from
  applying and is the core modification that makes a formal security proof possible. The deterministic
  variant cannot resample because it has no `r` to change.

- **BUFF security (Beyond UnForgeability Features)** — FN-DSA achieves stronger security notions
  than basic UF-CMA and SUF-CMA:
  - *Non-resignability*: a valid signature cannot be re-attributed to a different signer
  - *Exclusive ownership*: knowing the public key does not help forge for the corresponding secret key
  These properties are directly relevant to blockchain accountability and non-repudiation.

- **FFO Sampler now formally proven** — The EUROCRYPT 2026 paper provides the first formal proof of
  the FFO Sampler (Corollary 1: Rényi divergence bounded by ≈ 1 + 2aε²). The sampler's Gaussian
  output was previously justified only by analogy to the Klein Sampler. Both FALCON-DET1024 and
  FN-DSA use the FFO Sampler, so both benefit from this result.

- **Proof tightness** — The hardness assumptions are necessary, not just sufficient. Breaking
  FN-DSA is equivalent to solving t-R-ISIS — an attack on either directly yields an attack on the
  other. The Rényi divergence constants remain as proof overhead, but the equivalence itself is tight.

### Signature Format

- **Fixed-size signatures** — FN-DSA/1024 produces exactly 1280-byte signatures, matching the
  `FALCON_SIG_PADDED_SIZE(10)` defined in the Falcon specification. This padded format works
  reliably because rejections due to oversized compressed signatures can trigger a fresh nonce,
  allowing a retry. FALCON-DET1024 cannot retry and so must accept variable-length compressed
  signatures (up to 1423 bytes max).

- **Fixed size simplifies everything downstream** — buffer allocation, network framing, storage
  calculations, and block capacity planning all become deterministic when every signature is exactly
  1280 bytes.

### Implementation

- **Pure Rust implementations available** — FN-DSA has production-quality pure Rust implementations
  (e.g., Pornin's `rust-fn-dsa`, cited as `[Por25a, Por25b]` in the EUROCRYPT 2026 paper), with
  no C FFI, no libc linkage, and full Rust memory safety. FALCON-DET1024's reference implementation
  is C-only, requiring a C toolchain and carrying an unsafe FFI boundary in any Rust integration.

- **Floating-point handling** — FALCON-DET1024's C library mandates `FALCON_FPEMU=1` (blanket
  integer emulation of all floating-point) to guarantee cross-machine consistency, at a measured
  ~15x signing slowdown. FN-DSA implementations can use native `f64` on 64-bit platforms where
  strict IEEE-754 is guaranteed (x86_64, aarch64), falling back to software emulation only on
  32-bit hardware — consistent without the blanket performance penalty.

- **zkVM and embedded targets** — FN-DSA's pure Rust implementations support RISC-V (RV64GC) and
  modular crate structures that allow verification-only deployments, relevant for zkVM and
  light-client use cases.

### Protocol and Ecosystem

- **ABFT spec explicitly permits non-determinism** — The Algorand ABFT specification
  (Section 3, release 7791a63) states verbatim:

  > *"The signing procedure is allowed to produce a nondeterministic output, but the functions
  > above must be well-defined with respect to a given input to the signing procedure (e.g., a
  > procedure that implements Verify(Sign(...)) always returns the same value)."*

  The four things the protocol actually requires from `y = Sign(...)` are:
  1. **Validity** — `Verify(y, ...) ≠ 0` iff `y` was produced by `sk` (cryptographic correctness)
  2. **Total ordering** — a total order exists on possible outputs `y` (for sortition/committee selection)
  3. **Randomness extraction** — `Rand(y, pk)` yields a well-defined pseudorandom 256-bit value (for VRF-based leader selection)
  4. **Consistent verification** — `Verify(Sign(...))` always returns the same value

  Determinism — producing the same bytes every time — appears nowhere in this list.
  FN-DSA satisfies all four.

  **Node congruency** does not change this. All nodes agree on ledger state by receiving and
  verifying the *same broadcast signature bytes* — no node independently recomputes what a
  signature should be. Equivocation detection (Section 5.2 of the ABFT spec) is defined as two
  votes with *different proposal values* (`v1 ≠ v2`), not different signature bytes for the same
  vote. A non-deterministic scheme producing different bytes for the same `(I, r, p, s, v)` is
  not an equivocation in the spec's definition.

- **NIST FIPS standardisation** — FN-DSA is the forthcoming NIST standard. Hardware security
  modules, TPMs, and secure enclaves will eventually support it natively. Every language ecosystem
  will ship implementations. The deterministic variant will never receive this support.

- **Ecosystem interoperability** — Wallets, exchanges, and SDKs can use any standard FN-DSA
  library. Variant-specific tooling is not required. Using a non-standard variant forces every
  external developer to understand and implement an Algorand-specific deviation, compounding the
  integration burden across the ecosystem.

- **Domain separation context strings** — FN-DSA supports up to 255 bytes of per-call context,
  enabling explicit domain separation between transactions, state proofs, and consensus votes using
  the same key without collision risk.

- **Pornin's canonical implementation** — Thomas Pornin has implemented FN-DSA with Falcon+
  modifications in `rust-fn-dsa` (`[Por25a, Por25b]` in the EUROCRYPT 2026 paper). His design
  history is instructive: RFC 6979 made ECDSA deterministic because ECDSA nonce reuse directly
  exposes the private key — a critical vulnerability requiring a fix. For FN-DSA, poor randomness
  does not have the same catastrophic failure mode as ECDSA nonce reuse. Randomness in FN-DSA is
  primarily a security proof enabler, not a vulnerability patch. Pornin's choice to implement
  FN-DSA non-deterministically reflects this different mathematical context, not an abandonment of
  his prior preference for determinism.

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
    different "key" on each extraction, making Falcon-based IBE impossible. The "Do Not Disturb"
    paper explicitly mentions this use case (the Latte HIBE construction, under consideration for
    UK NCSC and ETSI standardisation).

  - *Sublinear SNARK aggregation*: The SNARK aggregation scheme for Falcon by Aardal et al.
    achieves asymptotically sublinear aggregated signature size specifically because of
    determinism. With FN-DSA, all salts must be included in the aggregated proof, forcing linear
    scaling. Determinism eliminates the salt overhead and enables sublinear aggregation.

  For Algorand's state proofs and transaction signing, neither of these hard requirements applies —
  but they do establish that the deterministic variant has legitimate use cases beyond convention.

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
  salts would need to be known by the verifier." This is correct in the theoretical sense — proof
  size scales with the number of included signers K rather than being constant. In practice, Algorand
  compact certificates include only a sampled subset K of signers (not all N participants), so the
  extra salt data would be approximately K × 40 bytes. At typical K values this is a real cost but
  not necessarily prohibitive. The approach is technically correct and could be made workable at
  Algorand's actual parameters; the spec's ruling is a succinctness engineering judgement, not an
  absolute impossibility.

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

True for the C library — and the spec explicitly acknowledges why. Floating-point units and
compiler optimisations like FMA (fused multiply-add) can produce slight discrepancies across
different devices, causing functionally inequivalent signing procedures. The spec mandates
`FALCON_FPEMU=1` as the solution, with a measured performance cost: signing is **~15x slower**
with FPEMU enabled (key generation ~2x slower; verification unaffected since it uses no FP).

The spec's own warning is precise: *"the same private key should not be used to sign the same
message digest using functionally inequivalent sampling procedures."* It states that if the
implementation ever changes (bug fix, optimisation, port to different hardware), the private key
or salt version must be refreshed.

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
address = SHA512/256("PqAddr" || pubkey_bytes)   // 32 bytes
```

This is consistent with how Algorand already derives addresses for MultiSig accounts
(`SHA512/256("MultisigAddr" || rest...)`) and LogicSig accounts (`SHA512/256("Program" || bytecode)`).

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

This is a genuine protocol change with performance implications. Mitigations:
- **Pre-fetching**: batch all state reads for a block's transactions in parallel before the
  verification pass
- **Key caching**: active accounts with stable FN-DSA keys have very high cache hit rates
- The state read is one step removed from the current model but is a well-understood pattern.

### Block Structure: Signature Storage

FN-DSA signatures at 1280 bytes vs Ed25519 at 64 bytes represent a 20x increase per transaction.
A SegWit-style separation addresses both block capacity and long-term storage:

```
Block {
    Header {
        txn_root   // existing — Merkle root of transaction payloads
        sig_root   // NEW — Merkle root of all signatures, same ordering
    }
    Body(txns  )   // permanent — sender, receiver, amount, etc. (no signatures)
    Witness        // prunable after BA* finality — actual signature bytes
}
```

Transaction ID is computed from payload only (not signature bytes). After Algorand's instant BA*
finality, the witness section can be pruned by most nodes. The `sig_root` persists permanently as
proof that all signatures were valid. Anyone needing to verify a historical signature requests it
from an archival witness node along with a Merkle inclusion proof, verifies the proof against the
known `sig_root`, then verifies the signature against the transaction's sender's registered pubkey.

Algorand's existing state proof infrastructure (vector commitments, Merkle trees) provides the
exact tooling this requires — it is an extension of a pattern already built into the protocol.

### Archival Storage

Archival nodes that retain the full witness section face a 20x increase in signature storage:
roughly 40 TB/year at 1,000 TPS vs ~2 TB/year today. Practical mitigations include:
- **Compression**: FN-DSA signatures pad to 1280 bytes; zero-padding compresses well, reducing
  effective size on disk
- **Time-bounded retention**: archival nodes could prune witness data beyond a threshold (e.g.,
  10 years) while `sig_root` persists forever
- **Tiered storage**: recent witness data on fast storage, historical on cold storage

### Batch Verification Loss

Ed25519 supports batch verification — verifying N signatures together via a single multi-scalar
multiplication is faster than N individual verifications. FN-DSA has no equivalent. Each signature
must be verified independently. Mitigations:
- **Parallel verification**: FN-DSA verifications are fully independent and parallelise trivially
  across CPU cores
- **SNARK aggregation** (longer-term): a block producer verifies all FN-DSA signatures and
  generates a single SNARK proof attesting their validity. Validators verify one proof instead of
  N signatures, making per-transaction verification overhead essentially zero. Active research area;
  lattice-friendly SNARK circuits are not yet efficient enough for production but the direction is clear.

---

## Use-Case Differentiated View

The strongest remaining argument for Falcon-DET1024 in Algorand is specific to state proof SNARKs: 
FN-DSA's public key binding requires participant public keys as SNARK circuit inputs, increasing proof complexity. This does not apply to transaction signing.

A reasonable differentiated approach:

| Protocol component | Recommended variant | Reason |
|---|---|---|
| Transaction signing | FN-DSA/1024 | pk binding, formal proof, NIST standard |
| State proof signing | FN-DSA/1024 without pk binding, or Falcon-DET1024 | SNARK circuit efficiency |
| Ephemeral consensus keys | Either (Qs≈1, security loss argument collapses) | Operational preference |

The conclusion that "FN-DSA vs Falcon-det is a binary choice" is likely false. Different protocol
components have different requirements and the optimal variant may differ across them.

---

## The "Do Not Disturb a Sleeping Falcon" Attack

A EUROCRYPT 2025 paper (Lin, Tibouchi, Yu, Zhang) identified a practical attack directly relevant
to the deterministic variant:

> *"When called twice on the same input with small floating-point discrepancies, the Falcon sampler
> has a small but significant chance of outputting two different lattice points with a very
> structured difference that immediately reveals the secret key."*

**The attack trigger:**

The sampler must be called **twice on the same input** with different floating-point errors. The
vulnerability arises from a discontinuity in Falcon's `SamplerZ` around near-integer center
values: a tiny FP error ε can flip `floor(c)`, and by Lemma 1 of the paper, when `floor(c)`
flips, the sampler executions are **guaranteed** to be inconsistent.

Near-integer centers occur with non-negligible probability at exactly four positions during
`ffSampling`: the first two and last two calls to `SamplerZ`. The probability at each is between
1/10,000 and 1/20,000 — mathematically derived from the NTRU key structure (1/q ≈ 1/12,289 for
the first two, 1/‖(g,−f)‖² for the last two). All other positions have denominator ≳ q²,
making integer centers negligibly rare and practically undetectable in double precision.

A discrepancy at the **last two** calls introduces a structured difference in just two components
of the output — specifically, `∆z0 = a + b·x^{n/2}` where a and b each range over at most 38
values ({-18,...,19}). Key recovery requires exhaustive search over at most 38² = 1,444 pairs —
less than 2^11 operations, essentially instant. A discrepancy at the **first two** calls produces
a short NTRU lattice vector — not currently believed to enable key recovery. The dangerous
condition (integer center at last two calls) fires at roughly 1 in 10,000–40,000 signing pairs,
as confirmed experimentally; key recovery follows from a single such pair via an exhaustive search
of 38² = 1,444 candidates.

The paper formally characterises the attack as violating **unbreakability under chosen-message
attacks** — a complete break of the standard security definition, not merely a practical concern.

**Why FN-DSA is not vulnerable — the precise reason:**

The paper states explicitly: *"For normal Falcon signatures, this should never happen, owing to
the use of a salt that never repeats."* With a fresh random salt on every signing call, the
sampler is **never called twice on the same input**, regardless of any FP discrepancies present.
The randomness makes the attack condition structurally impossible — not merely unlikely.

**Why FALCON-DET1024 is vulnerable — and FPEMU is not sufficient:**

In FALCON-DET1024, the random tape is derived deterministically as `SHAKE(ℓ || sk || msg)`, and
the fixed salt is `r = 0x00 || ℓ || "FALCON_DET" || 0x00...00` (40 bytes, with only the 1-byte
version field appearing in the signature). Signing the same message twice with the same key
therefore produces the identical sampler input every time.

The FALCON-DET1024 codebase acknowledges the FP risk: only `fpemu_det` (integer-emulated FP) is
the supported variant; `avx2_det`, `avx2_fma_det` and similar are present in the codebase but
explicitly unsupported and warned against in the README due to floating-point discrepancy risks.
The "Do Not Disturb" paper then identifies three concrete sources of FP discrepancy that can
trigger the attack even under the recommended configuration:

1. **IEEE-754 weak determinism** — even the same source code, compiler, and options can produce
   different results due to extended precision in x87 FPU registers.
2. **FMA-optimized code vs other variants** — experimentally confirmed to produce exploitable
   discrepancies at ~once per few thousand signing pairs, enabling full key recovery.
3. **The `sign_dyn` vs `sign_tree` API variants within the same FPEMU-enabled binary** — these
   two signing APIs compute the same floating-point operations in a subtly different order at the
   deepest recursive layer (n=4). Specifically, the `t1` component of the `split_fft` operation
   is computed as `0.5 × ((1/√2 × a) − (−1/√2 × b))` in `sign_dyn` and as
   `(1/(2√2)) × (a + b)` in `sign_tree` — mathematically equal, but not in IEEE-754 because FP
   arithmetic is not distributive. The resulting center discrepancy is passed to `SamplerZ`, where
   a near-integer input triggers the floor discontinuity. Crucially, **only centers are affected,
   not standard deviations** — consistent with the paper's proof that σ errors are non-dangerous.
   This occurs **even in `fpemu_det`**. Experimental results (Table 2 of the paper, 10 million
   queries per instance): `fpemu_det 1024` produces ~230-280 exploitable discrepant pairs per 10
   million sign_dyn + sign_tree pairs — approximately **1 in 40,000 pairs**. Over 70% of
   discrepancies occur at the last two SamplerZ calls, directly enabling key recovery. Table 3
   of the paper shows: `fpemu_det 1024` with **10,000 query pairs → 50% key recovery probability;
   100,000 query pairs → 90% key recovery probability**.

The FALCON-DET1024 authors correctly identified the unsupported FP variants as dangerous and
warned against them. The paper demonstrates that they missed a vulnerability in the configuration
they considered safe: using both signing APIs with the same key is sufficient to trigger key
recovery, even with integer FP emulation enabled.

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
Alternatively, the code base already contains a simpler n=2 or n=1 bottom layer that doesn't
have the re-ordering issue — skipping to it eliminates the discrepancy with no algorithmic change.
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

Figure 1 of the EUROCRYPT 2026 paper shows the two signing procedures side by side:

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
| No formal security proof | GPV proof fails; Falcon+ proof does not cover the deterministic variant. This was a known, deliberate tradeoff by Peikert (co-author of GPV itself) — the spec is honest about it. The gap became more pressing once the EUROCRYPT 2026 paper formalised it and proved the randomised variant secure |
| No public key binding | Multi-user security loss of ~20 bits at Algorand's account scale; completely absent from the spec |
| Salt absent (not just outside the loop) | Conditional distribution problem unresolvable without randomness |
| Variable-length signatures | Spec explicitly rejects padded format (1280 bytes) because the retry it requires would violate determinism |
| FP attack surface | "Do Not Disturb a Sleeping Falcon" (EUROCRYPT 2025): signing the same message twice with any FP discrepancy has a ~1/1000–1/3000 chance of instantly exposing the private key via a structured difference in sampler outputs — a risk the spec warned about but could not prevent |
| FPEMU does not fully protect | The "dynamic" vs "tree" API signing variants in the same FPEMU-enabled binary can produce exploitable discrepancies — FPEMU is necessary but not sufficient. A countermeasure exists (NewSamplerZ + odd key constraint) but requires re-keying: the C library always generates keys with `‖(g,−f)‖²` even, disqualifying all existing keys |
| C-only reference implementation | Libc linkage required; no pure Rust implementation exists for FALCON-DET1024 |
| Custom non-standard variant | No hardware acceleration, no ecosystem tooling, no multi-language library support |
| Determinism assumed but not required | ABFT spec never mandated it; inherited from Ed25519 convention |
| QROM security unproven | Even FN-DSA lacks a quantum random oracle model proof — an open problem noted in the EUROCRYPT 2026 paper |

---

## Verdict

The `falcon-det.pdf` spec itself scopes the deterministic variant to a specific use case: compact
certificates (state proofs) where SNARK efficiency requires a single shared digest across all
signers. The spec does not claim the deterministic variant is superior to randomized hashing in
general — only for that particular SNARK scenario.

On every dimension outside that specific use case — formal security, multi-user guarantees,
signature format, implementation quality, ecosystem alignment, and the "Do Not Disturb" FP attack
surface — FN-DSA/1024 is equal or superior. The deterministic variant's practical advantages are:
it was designed and deployed before FN-DSA existed, it avoids SNARK circuit input cost for compact
certificates, and it matches existing Ed25519 conventions that some tooling may rely on.

The Algorand PQ migration is a natural moment to evaluate FN-DSA as the primary signing primitive
for transaction signing, while considering the state proof component separately given its SNARK
efficiency constraints. Whether to migrate, and on what timeline, is ultimately a protocol design
decision that weighs the security and standardisation arguments here against operational continuity,
testing burden, and the maturity of the FN-DSA standard itself.

**Timing caveat:** FN-DSA has not yet been fully finalised as FIPS 206. Production deployment
should be timed with or after NIST finalisation. Building and testing against current
implementations is appropriate; shipping in production is premature until the standard lands.

---

## References

- Fouque (Université de Rennes, IUF), Gajland (IBM Research Zurich), de Groote (ENS Paris-Saclay),
  Janneck (Ruhr University Bochum), Kiltz (Ruhr University Bochum) —
  *A Closer Look at Falcon*, IACR ePrint 2024/1769 (received 2024-10-30, last revised 2026-03-02).
  A major revision of an IACR publication in EUROCRYPT 2026.
  Short URL: https://ia.cr/2024/1769
- Lin, Tibouchi, Yu, Zhang — *Do Not Disturb a Sleeping Falcon: Floating-Point Error Sensitivity
  of the Falcon Sampler and Its Consequences*, IACR ePrint 2024/1709, EUROCRYPT 2025.
  Acknowledged by both Chris Peikert (FALCON-DET1024 co-designer) and Thomas Pornin (Falcon
  principal author) prior to publication.
- Lazar, Peikert — *Deterministic Falcon-1024*, `falcon-det.pdf`, Algorand Inc., November 2021:
  https://github.com/algorand/falcon/blob/main/falcon-det.pdf
- Pornin — `rust-fn-dsa` (2025): https://github.com/pornin/rust-fn-dsa
- Pornin — RFC 6979, *Deterministic Usage of DSA and ECDSA*, 2013
- Algorand ABFT Specification, Section 3 — Identity, Authorization, and Authentication (release 7791a63):
  https://github.com/algorandfoundation/specs/releases/tag/7791a63
- NIST FIPS 206 (FN-DSA draft)
