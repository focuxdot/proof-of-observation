# Proof-of-Observation Protocol, Version 1

Status: **Draft Standard**
Signing domain: `tee-exchange-v2`
Wire version: `2`

## Abstract

The Proof-of-Observation Protocol lets the **end user of an API relay**
cryptographically verify that a response they received is the genuine,
byte-for-byte output served by a named upstream endpoint for their own request —
**without having to trust the relay that sat in the middle**.

A relay component running inside a Trusted Execution Environment (TEE) observes
the TLS-terminated exchange with the upstream, signs a compact statement that
binds the routing facts and the request/response content together, and emits
hardware attestation proving that the signing key belongs to a known, auditable
enclave image. A verifier holding only its own request bytes and the received
response bytes can independently check every claim offline.

This document specifies the wire formats, the canonical signing statement, and
the verification procedure normatively, so that independent implementations can
interoperate. It deliberately specifies **integrity and authenticity, not
confidentiality** (§8).

## 1. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when,
they appear in all capitals.

Roles are named after the RATS architecture (RFC 9334):

| Role | This protocol |
|------|---------------|
| **Attester** | The TEE-resident egress component that observes the upstream exchange and produces Evidence (attestation document) and a signed Exchange Statement. |
| **Verifier** / **Relying Party** | The end user's client, which appraises Evidence and the Statement. In v1 these two RATS roles are co-located in the client. |
| **Endorser** | The TEE manufacturer whose root of trust signs the attestation certificate chain (v1: AWS Nitro root). |
| **Reference Value Provider** | The publisher of the expected enclave measurement (PCR0) derived from a reproducible build of the public Attester source. |

Other terms:

- **Exchange Statement** (or *Statement*): the canonical byte string defined in §5 that the Attester signs.
- **Evidence**: the TEE attestation document (§6) binding the Statement-signing public key to a hardware-rooted measurement.
- **Reference Value**: the expected enclave measurement (PCR0) a Verifier compares against.
- **Octet**: an 8-bit byte. All lengths are in octets unless stated otherwise.

## 2. Protocol Overview

Verification rests on two independent cryptographic layers that the Verifier
checks together:

1. **Statement layer (application).** The Attester signs an Exchange Statement
   (§5) with an Ed25519 key generated inside the TEE. The Statement binds the
   upstream routing facts (host, path, method, status, content-type) to the
   SHA-256 digests of the request and response bodies.

2. **Evidence layer (hardware).** The Attester emits a TEE attestation document
   (§6) that (a) is signed by a certificate chain rooted in the TEE
   manufacturer's pinned root, and (b) carries, in an attested field, the public
   key of the Statement-signing Ed25519 key and a measurement (PCR0) of the
   enclave image.

The trust argument is transitive: hardware root → attested enclave measurement →
attested Ed25519 public key → signed Statement → request/response digests the
Verifier recomputes from bytes it already holds. No step requires trusting the
relay operator.

```
 AWS Nitro root  ──signs──▶  enclave cert chain
        │
        ▼  (Evidence, §6)
 PCR0 == Reference Value   AND   attested public_key == proof.public_key
        │
        ▼  (Statement layer, §5)
 Ed25519.verify(public_key, statement, signature) == true
        │
        ▼
 SHA-256(my request bytes)  == request-body-sha256
 SHA-256(received bytes)     == response-body-sha256
```

## 3. Cryptographic Primitives

A v1 implementation:

- MUST use **SHA-256** (FIPS 180-4) for request- and response-body digests.
- MUST use **Ed25519** (RFC 8032) for the Statement signature.
- MUST verify Evidence according to the TEE profile in effect. The v1 profile
  (§6) uses **COSE_Sign1** (RFC 9052) with **ECDSA P-384 / SHA-384 (ES384)** and
  an X.509 (RFC 5280) chain.

Digest and signature values are encoded as specified per field in §5 and §7.
Algorithm identifiers are carried in the wire envelope (§7) and bound by the
signing domain string (§9); a Verifier MUST NOT accept an algorithm it does not
recognize.

## 4. Scope of the Guarantee

This protocol answers exactly the questions in the table below. §8 states the
threat model in full.

| User concern | Mechanism |
|---|---|
| The response is the upstream's verbatim output, unaltered | `response-body-sha256` |
| It was sent to the named **upstream endpoint**, for the model I asked for | `upstream-host` + `upstream-path` (signed) + model echoed in the verified response body |
| The response answers **my** request, unmodified | `request-body-sha256` |
| It is fresh, not a replayed old response | `nonce` bound into Evidence + short-lived attestation certificate |
| (Not provided) Confidentiality of prompt/response | Out of scope; the proof carries digests only |

## 5. The Exchange Statement (Normative)

### 5.1 Canonical byte layout

The Exchange Statement is a UTF-8 octet string of exactly nine lines, each line —
**including the first (domain) line and the last** — terminated by a single LF
(`0x0A`). There is no other whitespace, no CR, and no trailing octet after the
final LF.

```
tee-exchange-v2\n
nonce=<nonce>\n
upstream-host=<host>\n
upstream-path=<path>\n
http-method=<method>\n
http-status=<status>\n
resp-content-type=<content-type>\n
request-body-sha256=<reqhash>\n
response-body-sha256=<resphash>\n
```

ABNF (RFC 5234), where `LF = %x0A`:

```
statement   = domain LF
              "nonce="                nonce          LF
              "upstream-host="        host           LF
              "upstream-path="        path           LF
              "http-method="          method         LF
              "http-status="          status         LF
              "resp-content-type="    content-type   LF
              "request-body-sha256="  hexdigest      LF
              "response-body-sha256=" hexdigest      LF
domain      = "tee-exchange-v2"
nonce       = 1*(base64-char)          ; RFC 4648 §4 alphabet incl. '=' padding
host        = 1*(%x21-7E)              ; no CR/LF/SP
path        = 1*(%x21-7E)
method      = 1*(%x41-5A)              ; uppercase A-Z
status      = 3DIGIT
content-type = 1*(%x20-7E)             ; may contain '=' and ';'
hexdigest   = 64(HEXDIG-lower)         ; SHA-256, lowercase hex
```

The first line is the bare domain constant `tee-exchange-v2`; it is NOT a
`label=value` pair. All subsequent lines are `label=value` pairs.

### 5.2 Field normalization (Normative)

The Attester MUST derive each value as follows; a Verifier reconstructing the
Statement (§8.1) MUST apply the identical transforms before comparison.

| Field | Source | Normalization |
|---|---|---|
| `nonce` | Per-exchange nonce | base64 (RFC 4648 §4, with `=` padding). The **same octets** MUST appear in the Evidence nonce field (§6). |
| `upstream-host` | The host the Attester actually connected to and validated the upstream certificate against | Lowercased (ASCII). |
| `upstream-path` | Request path | The substring **before the first `?`** (query string removed). |
| `http-method` | Request method | Uppercased (ASCII). |
| `http-status` | Upstream response status | Decimal, no leading zeros. |
| `resp-content-type` | Upstream `Content-Type` response header | **Verbatim**, including any `; charset=…` parameter. |
| `request-body-sha256` | Request body octets | `SHA-256`, lowercase hex. No canonicalization of the body. |
| `response-body-sha256` | Response body octets | `SHA-256`, lowercase hex. No canonicalization of the body. |

Bodies are treated as **opaque octet strings**: the digest is taken over the
exact bytes the user sent and the exact bytes the user received. There is no
JSON/headers/transfer canonicalization, by design — the Verifier already holds
those exact octets.

### 5.3 Parsing and injection safety (Normative)

- A parser MUST split each `label=value` line at the **first** `=` octet only.
  This keeps values that themselves contain `=` (e.g.
  `resp-content-type=text/event-stream; charset=utf-8`) intact.
- No reconstructible field (`nonce`, `upstream-host`, `upstream-path`,
  `http-method`, `http-status`, `resp-content-type`) may contain CR (`0x0D`) or
  LF (`0x0A`). An Attester MUST reject an inbound request or upstream response
  whose to-be-signed fields contain CR or LF, and MUST NOT emit a Statement for
  it. (This is what makes the LF-delimited layout unambiguous.)
- A Verifier MUST treat any Statement that does not parse as exactly nine
  LF-terminated lines in the order of §5.1 as a verification failure.

> Note: in a future major version the canonical layout MAY be replaced by a
> length-prefixed or deterministic-CBOR encoding to remove the textual
> delimiter constraint entirely; see §9. v1 implementations MUST use the textual
> layout above.

### 5.4 Fields intentionally NOT signed (Normative)

A v1 Statement MUST NOT include, and a Verifier MUST NOT expect:

- **Request or response headers** (other than the response Content-Type, which
  is signed). Headers are relay metadata the user has no reference value for.
- **The query string** of the request path (removed per §5.2).
- **Injected `Authorization` / API-key material.** These MUST always be excluded.
- **Any Attester-asserted wall-clock timestamp.** Freshness derives solely from
  the Evidence nonce and certificate validity (§6), never from a self-asserted
  time.
- **The upstream dial IP / `host:port`.** Only the validated host **name** is
  signed.

§8.3 states the residual risk these exclusions accept.

## 6. Attestation Evidence

Evidence is the TEE attestation that binds the Statement-signing key to attested
hardware. The verification procedure (§8.3) is **profile-independent**; the
concrete envelope, signature algorithm, and root of trust are supplied by an
**Evidence profile**. v1 defines exactly one profile, **`nitro`** (§6.2); the
in-effect profile is identified out of band (by the deployment's published
Reference Value and pinned root). A Verifier MUST reject Evidence whose profile it
does not implement (§9).

### 6.1 Profile-independent requirements (Normative)

Every Evidence profile MUST let a Verifier establish, by checking the Evidence,
all of:

- **Manufacturer-rooted authenticity.** The Evidence is signed by a chain (or
  equivalent) terminating in a **root of trust the Verifier pins out of band** (the
  TEE manufacturer's root), such that only that manufacturer's genuine attestation
  service could have produced it.
- **An enclave measurement.** A profile-defined measurement of the loaded image
  (the Reference Value compared in §8.5) — e.g. a PCR, an MRENCLAVE/MRTD, or an EAT
  measurement claim.
- **The attested Statement public key.** The Ed25519 public key of §5, in an
  attested field, so §8.3 step 6 can bind the application signature to the hardware.
- **The nonce.** The per-exchange nonce octets (§5/§7), in an attested field, for
  the freshness binding of §8.4.
- **Freshness of the Evidence itself.** A profile-defined liveness mechanism (e.g.
  a short-lived certificate window, or a fresh-nonce challenge) bounding how old the
  Evidence may be.

A profile MUST define exactly how each is encoded and verified, and MUST fail
closed: any element absent, malformed, or unverifiable is a verification failure.
A hardened decoder SHOULD bound nesting depth, item counts, and string lengths
against malicious Evidence regardless of profile.

### 6.2 The `nitro` profile (Normative for v1)

The `nitro` Evidence is an AWS Nitro Enclaves attestation document: a CBOR (RFC 8949)
`COSE_Sign1` structure (RFC 9052) — a 4-element array
`[protected, unprotected, payload, signature]`. The `payload` is a CBOR map
containing at least:

| Key | Meaning |
|---|---|
| `certificate` | DER leaf certificate (the enclave's ephemeral attestation cert). |
| `cabundle` | Array of DER certificates from root to intermediate. |
| `pcrs` | Map of PCR index → measurement octets. **PCR0** (SHA-384, 48 octets) is the enclave image measurement. |
| `public_key` | The **Ed25519 public key** (SPKI) of the Statement-signing key (§5). |
| `nonce` | The per-exchange nonce octets; MUST equal the `nonce` carried in the proof (§7) and Statement (§5). |
| `user_data` | OPTIONAL application data. Not used for binding in v1. |

A Verifier appraising `nitro` Evidence MUST check **all** of:

1. **Envelope.** `payload` decodes to a CBOR map; `certificate`, each `cabundle`
   entry, `pcrs[0]`, and `public_key` are present and well-typed.
2. **COSE signature.** Reconstruct the COSE `Sig_structure`
   `["Signature1", protected, h'' , payload]` (empty external_aad) and verify it
   under the leaf certificate's public key using **ES384** (ECDSA P-384 over
   SHA-384, IEEE P1363 signature encoding).
3. **Certificate chain.** Each certificate in `cabundle` (root → … →
   intermediate) followed by the leaf forms a valid signature chain
   (`chain[i]` is signed by `chain[i-1]`).
4. **Pinned root.** The chain's root is self-signed AND its SHA-256 fingerprint
   equals the pinned manufacturer root. For the `nitro` profile the pinned AWS
   Nitro root (G1) fingerprint is:
   `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
5. **Validity window (freshness).** Every certificate in the chain is within its
   `notBefore`/`notAfter` window at verification time. The leaf is short-lived
   (hour-scale); an expired leaf indicates stale Evidence. A Verifier MUST treat
   an out-of-window certificate as a freshness failure. Authenticity of an
   already-verified Statement is unaffected, so a Verifier MAY surface expiry as
   a soft warning distinct from a signature failure.

On success the Verifier obtains, **attested**, the values `public_key`, `pcr0`,
and `nonce`, which feed §8.

A hardened decoder SHOULD bound CBOR nesting depth, container item counts, and
string lengths against malicious Evidence.

### 6.3 Defining a new Evidence profile (Normative for profiles)

To extend Proof-of-Observation to another TEE, a new profile MUST specify, against
the §6.1 requirements:

1. the **Evidence envelope** format and how it is parsed;
2. the **signature algorithm** and how the manufacturer-rooted chain (or
   equivalent) is verified;
3. the **root of trust** and how a Verifier pins it;
4. where the **measurement**, the **attested Statement public key**, and the
   **nonce** live, and how each is extracted;
5. the **freshness** mechanism (§6.1) and any validity window;
6. a stable **profile identifier** and how it is signalled (§9), plus published
   test vectors (§11).

The verification procedure (§8) is otherwise unchanged across profiles: only the
§8.3 step-5 appraisal and the §8.5 Reference Value are profile-specific; the
Statement check (§8.1), the content bindings (§8.2), and the key/nonce bindings
are profile-independent.

> *Non-normative sketch — a future `tdx` / EAT profile.* An Intel TDX or AMD
> SEV-SNP deployment would carry Evidence as an EAT (RFC 9711) or vendor quote: the
> manufacturer root becomes the Intel/AMD attestation root (verified via that
> vendor's quote verification, e.g. DCAP), the measurement becomes the
> MRTD/MRENCLAVE / report measurement, and the Statement public key and nonce are
> carried in attested claims (an EAT `nonce` claim plus an application claim). Such
> a profile is not defined in v1; it is shown only to demonstrate that §6.1 is
> TEE-neutral.

## 7. Proof Wire Format (Normative)

The proof is delivered to the Verifier out of band (e.g. alongside or after the
response stream) as a JSON object:

```json
{
  "v": 2,
  "alg": "ed25519",
  "public_key": "<base64 SPKI of the Ed25519 signing key>",
  "nonce": "<base64>",
  "upstream_host": "api.example.com",
  "upstream_path": "/v1/messages",
  "http_method": "POST",
  "http_status": 200,
  "resp_content_type": "text/event-stream",
  "request_body_sha256": "<lowercase hex>",
  "response_body_sha256": "<lowercase hex>",
  "signature": "<base64 Ed25519 signature over the §5 Statement>",
  "attestation": "<base64 COSE_Sign1 Evidence, §6>",
  "pcr0": "<lowercase hex; advisory copy, see §8.4>"
}
```

- `v` MUST be `2` for this version. A Verifier MUST reject envelopes whose `v` it
  does not implement.
- The fields `nonce`, `upstream_host`, `upstream_path`, `http_method`,
  `http_status`, `resp_content_type`, `request_body_sha256`,
  `response_body_sha256` are the **reconstruction inputs** for the §5 Statement,
  carried verbatim. The Verifier reassembles the Statement octets from these
  values (applying §5.2/§5.3) — it does NOT trust them until the signature
  verifies.
- `pcr0` in the envelope is advisory only; the authoritative PCR0 is the one
  extracted from verified Evidence (§6), not this field.

## 8. Verification Procedure (Normative)

A conforming Verifier holds: its own **request body octets**, the **received
response body octets**, the proof (§7), and a trusted **Reference Value** (§8.5).
It MUST perform all of the following and fail closed on any failure.

### 8.1 Reconstruct and verify the Statement

1. Reassemble the §5.1 octet string from the §7 reconstruction inputs, applying
   the normalization of §5.2 and the parsing constraints of §5.3.
2. Verify `Ed25519.verify(public_key, statement, signature)` is true, where
   `public_key` is `proof.public_key`. On failure → **fail**.

After this step the routing facts (`upstream_host`, `upstream_path`,
`http_method`, `http_status`, `resp_content_type`) are trusted as signed and MAY
be displayed to the user.

### 8.2 Verify the content bindings

3. `SHA-256(my request body octets)` MUST equal `request-body-sha256`.
4. `SHA-256(received response body octets)` MUST equal `response-body-sha256`.

Either mismatch → **fail** (the proof does not correspond to this exchange).

### 8.3 Verify Evidence and the key binding

5. Appraise `proof.attestation` per §6 (all checks). On failure → **fail**.
6. The attested `public_key` from Evidence MUST equal `proof.public_key` used in
   step 2. This is the binding that ties the application signature to attested
   hardware. On mismatch → **fail**.

### 8.4 Verify freshness

7. The attested `nonce` from Evidence MUST equal `proof.nonce` (and hence the
   `nonce` line verified in the Statement). On mismatch → **fail**.
8. Evidence certificate validity (§6 step 5) gates freshness as specified there.

### 8.5 Verify the enclave measurement against a Reference Value

9. The attested `pcr0` MUST equal a Reference Value the Verifier trusts. The
   Reference Value is the PCR0 produced by a reproducible build of the **public
   Attester source** at a published release. A Verifier SHOULD obtain it from the
   reproducible-build procedure (independently reproducible by the Verifier or a
   third party) rather than from the relay. On mismatch → **fail**.

### 8.6 Model attribution (informative)

The model that produced the response is read from the **already-verified**
response body (host+path are signed and the response is integrity-bound, so the
response's self-reported model is authoritative). It is therefore NOT a separate
signed field.

## 9. Versioning and Crypto Agility

- The signing **domain string** (`tee-exchange-v2`) is the version and
  cross-protocol separator: it is the first line of every Statement, so a
  signature for one domain can never validate under another. Any change to the
  Statement layout, field set, normalization, or signature algorithm MUST change
  the domain string and the wire `v`.
- A Verifier MUST reject a domain string, `v`, `alg`, or Evidence profile it does
  not implement, rather than attempting a best-effort interpretation.
- Future versions MAY: add fields (e.g. token/usage accounting), replace the
  textual layout (§5) with deterministic CBOR, or add TEE profiles (§6) beyond
  `nitro`. Such changes are major-version changes under the rule above.

## 10. Security Considerations

### 10.1 What this protocol proves

For an exchange whose proof verifies under §8, the Verifier has cryptographic
assurance that:

- The response body is the **verbatim, unaltered** output returned over a TLS
  session the Attester established **to the named `upstream_host`** (whose
  certificate the Attester validated), for the request whose body hashes to the
  signed `request-body-sha256`.
- The signing key is bound to an enclave whose image measurement (PCR0) matches a
  reproducible build of public source — i.e. the relay operator could not
  substitute arbitrary code in the signing path without changing PCR0 and
  failing §8.5.
- The Evidence is fresh (nonce-bound, short-lived certificate), so the proof is
  not a replay of an unrelated prior exchange.

### 10.2 What this protocol does NOT prove

- **Confidentiality.** The proof carries digests, not plaintext, but the protocol
  makes **no confidentiality claim** about the prompt or response: a relay /
  parent instance may transiently handle plaintext. Users requiring
  confidentiality must obtain it by other means.
- **Public verifiability of content.** Because bodies are committed as digests,
  only a party that already holds the plaintext (normally the requesting client)
  can verify the body bindings (§8.2). A third party can verify the Statement
  signature and Evidence, but cannot confirm the digests correspond to any
  particular content. This protocol is **counterparty-verifiable, not
  publicly-verifiable** with respect to content.
- **Anything about traffic that carried no proof.** A response without a
  verifying proof is simply unattested; see §10.5.

### 10.3 Residual risks accepted in v1

Because headers and the request query string are unsigned (§5.4), a malicious
relay could in principle alter request-side feature toggles (e.g. a
`feature-flag` header or a `?beta=` query parameter) and thereby nudge upstream
behavior. It cannot, however, alter the **model** (carried in the signed request
body), the **endpoint resource** (`upstream_host` + `upstream_path` are signed),
the **prompt** (request body digest), or the **response** (response body digest).
v1 judges this residual acceptable. Implementations that need query-string or
header binding MUST define a new version (§9).

### 10.4 Canonicalization robustness

The textual Statement layout depends on the CR/LF exclusion of §5.3 for
unambiguous parsing; an Attester that fails to enforce that exclusion could emit
an ambiguous Statement (e.g. via a crafted `resp-content-type`). Implementations
MUST enforce §5.3. A future version SHOULD migrate to a length-prefixed or
deterministic-CBOR encoding to remove this dependency structurally.

### 10.5 Coverage and selective attestation

This protocol attests **individual exchanges**. It does not, by itself, prove
that *all* of a user's traffic was attested: a relay could serve verifying proofs
for some exchanges and route others through an unattested path. Deployments that
need a whole-account or whole-endpoint coverage guarantee MUST layer an
additional mechanism (e.g. a coverage commitment or transparency log) on top of
this protocol; such a mechanism is out of scope for v1.

### 10.6 Trust in the Reference Value

The §8.5 measurement check is only as strong as the Verifier's trust in the
Reference Value. A Reference Value asserted by a single party reduces to trusting
that party. Deployments SHOULD make the Reference Value independently reproducible
(reproducible build of the public Attester source) and SHOULD work toward
multi-party or transparency-log-backed publication so that the measurement does
not rest on a single publisher.

### 10.7 Trust assumptions (what a Verifier trusts instead of the relay)

This protocol does not eliminate trust; it **relocates** it from the relay
operator to a small, public, hardware-rooted base. A Verifier that accepts a
proof is trusting, in the relay's place:

- **The TEE manufacturer's root and attestation service.** Evidence is only as
  sound as the pinned root (§6 step 4) and the manufacturer's attestation signing.
  A manufacturer that is compromised — or compelled — to issue Evidence for an
  image it did not actually run could forge attestation. A deployment reduces this
  single-vendor dependence by supporting multiple, independently-rooted TEE
  profiles (§9), so that no one manufacturer is a sole point of trust.
- **The integrity of the TEE itself.** A break of the TEE's isolation or
  measurement (side-channel key extraction, a measurement-spoofing flaw) would let
  an attacker sign arbitrary Statements under a valid PCR0. This protocol inherits
  the security of the underlying TEE; it does not strengthen it.
- **The benign-ness of the measured source.** Reproducible build (§8.5) proves the
  running image equals *public source* — not that the source is free of a subtle
  backdoor. The Attester is therefore kept deliberately small and is intended to
  be independently audited; the guarantee is "the running code is exactly this
  auditable code," not "this code is correct." A minimal TCB and independent audit
  are load-bearing.

These are strictly weaker assumptions than trusting an opaque relay — they are
public, pinnable, reproducible, and auditable, where relay behavior is none of
those — but they are not zero, and an honest deployment states them plainly.

## 11. Conformance

An implementation is a **conforming Verifier** if it performs every MUST in §8
(and §5, §6, §7) and fails closed on any failure.

An implementation is a **conforming Attester** if every Statement it emits
parses per §5 and verifies per §8 against Evidence it emits per §6.

### 11.1 Test vectors

Implementations MUST reproduce the canonical Statement bytes for the published
test vectors. Each vector supplies the §5.2 field inputs plus the request/response
body octets, and the expected Statement (both UTF-8 and as a hex octet dump),
the request-body digest, and the response-body digest. The published vector set
covers at least:

- a basic exchange exercising host lowercasing, query-string removal, method
  uppercasing, and a `content-type` containing `; charset=…`;
- an already-normalized exchange;
- empty request and response bodies;
- non-ASCII (UTF-8) bodies hashed identically on both sides.

A conforming implementation MUST, for every vector, produce a Statement whose
octets equal the vector's expected octets exactly, and digests equal to the
expected digests.

## 12. References

Normative:

- BCP 14 — RFC 2119, RFC 8174 (requirement keywords)
- RFC 8032 — Ed25519
- FIPS 180-4 — SHA-256, SHA-384
- RFC 9052 — COSE_Sign1
- RFC 8949 — CBOR
- RFC 5280 — X.509 / PKIX
- RFC 5234 — ABNF
- RFC 4648 — Base64 / Base16 (hex)

Informative:

- RFC 9334 — RATS architecture (role model used in §1)
- RFC 9711 — Entity Attestation Token (EAT) — candidate Evidence envelope for a
  future TEE-neutral profile (§6, §9)
- AWS Nitro Enclaves attestation document specification

## Appendix A. Related Work (Informative)

Proof-of-Observation occupies the space of **verifiable provenance for data
obtained through an intermediary**, alongside several other approaches with
different trust and capability trade-offs.

- **TLS attestation via MPC — TLSNotary, DECO.** A notary co-runs the client's
  TLS session under secure multi-party computation, so neither party alone can
  forge the transcript, yielding a proof that a TLS server returned certain bytes.
  These need no special hardware but add MPC round-trips and require the notary
  online during the session. Proof-of-Observation instead **terminates the
  upstream TLS inside a TEE** and signs the observed exchange — it depends on
  attestation hardware but needs no MPC and no third party online at verification
  time.
- **ZK / web-proof systems — "zkTLS" (Reclaim, zkPass, Pluto, …).** These produce
  zero-knowledge proofs about TLS-fetched data, often enabling *selective
  disclosure* and *public verifiability* of a property of the content.
  Proof-of-Observation is **counterparty-verifiable, not publicly-verifiable**
  with respect to content (§10.2) and offers no selective disclosure; in exchange
  it is a thin signature over digests with no per-statement proving cost, and it
  binds *the verifier's own request* to the response.
- **IETF RATS (RFC 9334) and EAT (RFC 9711).** This protocol *uses* the RATS role
  model (§1) and treats EAT as the candidate envelope for a TEE-neutral Evidence
  profile (§9). RATS standardizes *how attestation is conveyed and appraised*;
  Proof-of-Observation adds the application layer above it — the signed Exchange
  Statement binding routing facts to request/response content — that RATS does not
  itself define.
- **Content provenance — C2PA.** C2PA signs the provenance and edit history of a
  media asset at creation time. Proof-of-Observation signs the *transport
  exchange* (which upstream returned which bytes for which request), not authorship
  of content; the two are complementary — a relay could carry C2PA-signed content
  inside a Proof-of-Observation-attested exchange.

Distinguishing properties of this protocol: (a) the proof binds **the verifier's
own request** to the response, not merely "some bytes from a server"; (b)
verification is a thin offline signature + digest check — no MPC, no ZK proving,
no online third party; (c) the trust base is a **reproducibly measured, publicly
auditable** enclave image (§10.7) rather than a notary or a proving circuit. The
costs are the dependence on attestation hardware and the lack of public
content-verifiability.
