# proof-of-observation

> Cryptographic proof that an API response is genuine — verifiable by the end user, **without
> trusting the relay that served it**.

`proof-of-observation` is a reproducible **AWS Nitro Enclave** that sits at a relay's egress and
turns *"trust me, this response is real"* into something a client can **check for itself**.

```
        you                relay (untrusted)         AWS Nitro Enclave    ───▶  upstream API
         |   request             |                   (measured by PCR0)
         | --------------------> | ---------------->  (1) terminate upstream TLS, verify cert
         |                       |                    (2) stream response + hash (no buffering)
         |  response + tee.proof |                    (3) sign tee-exchange-v2 statement (Ed25519)
         | <-------------------- | <---------------   (4) attest: bind {signing key, PCR0} -> AWS root
         v                                                signing key never leaves the enclave
   verify locally, trusting only AWS's root:
     (1) attestation chains to AWS Nitro root     (3) received bytes hash to the signed statement
     (2) PCR0 == your reproducible build           (4) signing key bound by attestation; nonce fresh
```

## How it works

For each request, the enclave:

1. **terminates the upstream TLS connection inside the enclave** — validating the upstream's
   certificate against a CA bundle compiled into the measured image;
2. **streams the response back while hashing it** — no full-body buffering;
3. **signs a `tee-exchange-v2` field-decomposition statement** (Ed25519) that binds the route
   (host / path / method / status / content-type) and the request & response body hashes;
4. attaches an **NSM attestation** binding the signing public key and the enclave's **PCR0** to
   the AWS Nitro root.

The signing key is generated at boot and **never leaves the enclave**.

A client — in the browser or a CLI — then verifies, end-to-end and offline:

- the attestation **chains to the AWS Nitro root** (a root *you* pin from AWS's own docs);
- the enclave's **PCR0 matches** a value you reproduced from this source (below);
- the response bytes you received **hash to** what the enclave signed;
- the signing key is **bound** by the attestation, and the **nonce is fresh** (anti-replay).

Pass all checks ⟹ the response provably came from the named upstream and was not altered — even
though the relay itself never had to be trusted.

## What it does *not* guarantee

An **integrity / authenticity** guarantee, **not confidentiality**: the relay still transiently
handles plaintext (it is just never persisted). If your threat model requires the operator to be
unable to *read* the traffic, this does not cover it. See [`docs/TEE.md` §2](docs/TEE.md).

## Why you can trust the PCR0

The whole scheme rests on one thing: the PCR0 a client compares against must be **independently
recomputable from public source** — not a number the operator asserts. The enclave's entire
measured TCB lives in [`enclave/`](enclave); built twice with a pinned toolchain it yields a
**byte-identical** PCR0. See [`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md).

## Repository layout

| Path | What |
|---|---|
| [`enclave/`](enclave) | The measured Rust enclave — the trust-critical TCB that PCR0 measures |
| [`verifier/`](verifier) | The proof verifier (TypeScript / JS) + golden test vectors |
| [`docs/`](docs) | Architecture, the v2 signing spec, the reproducible-build procedure |
| [`docs/tee-verify.html`](docs/tee-verify.html) | A self-contained **browser verifier** — paste a response, verify locally |

## Verify a response

A streamed response carries a trailing `event: tee.proof`. Save the whole stream, then:

```bash
# CLI
npx tsx verifier/tee-verify-stream.ts captured.sse --pcr0 <canonical-PCR0>
```

…or open [`docs/tee-verify.html`](docs/tee-verify.html) in a browser and paste the stream — it
verifies entirely on your machine. Full walkthrough: [`docs/TEE.md` §3](docs/TEE.md).

## Reproduce the PCR0

```bash
cd enclave
bash reproducible-build.sh        # double --no-cache build → two byte-identical PCR0s
```

Compare the result against the canonical value in
[`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md) **and** against a running
enclave's attestation. A three-way match (your build == doc == live attestation) proves the
running enclave is compiled from exactly this source, with nothing smuggled in.

> Requires an `aarch64` host with Docker + the AWS Nitro CLI (pinned versions in the doc).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
Third-party attribution: [`NOTICE`](NOTICE).
