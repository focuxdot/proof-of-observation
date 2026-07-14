# proof-of-observation enclave (`attest`)

The measured AWS Nitro enclave that performs **attested observation**: it terminates the
upstream TLS connection *inside* the enclave,
streams and hashes the response, and signs an observation over a `tee-exchange-v2`
field-decomposition statement (Ed25519). The signing key is generated at boot and **never
leaves the enclave**; an NSM attestation binds the signing public key + PCR0 to the AWS
Nitro root.

This crate is the **trust-critical core** — what it does is exactly what the published PCR0
measures, so it is meant to stay small and to change rarely.

## What is measured (TCB boundary)

Compiled into `/attest` and measured by PCR0:

- `Cargo.toml`, `Cargo.lock`, `Dockerfile`
- `src/{main.rs, lib.rs, tls_profile.rs, h2_client.rs, egress_boring.rs, egress_openssl.rs, egress_rustls_aws_lc.rs}`
- `src/ca-bundle.pem`

**Not** measured (test-only, a separate binary, or not `COPY`-ed into the build image):

- `src/bin/profile-encode.rs` — a separate offline encoder binary. `cargo build` compiles it, but only `/attest` is `COPY`-ed into the image, so its contents never affect PCR0
- `tests/` — golden vectors, run via `cargo test`
- `signing-vectors.json` — `#[cfg(test)]` golden; stripped from the release binary, not in the image
- `specs/*.json` — example profiles for the `profile-encode` tool
- `*.sh` / `*.py` / `*.service` — host-side operations, not the enclave

## Build it reproducibly / verify PCR0

The point of a measured PCR0 is that anyone can recompute it from source. Full procedure:
[`../docs/tee-reproducible-build.md`](../docs/tee-reproducible-build.md). In short:

1. On an `aarch64` host with the pinned toolchain (Docker + Nitro CLI versions in that doc),
   build twice with `--no-cache`; the two PCR0s must be byte-identical. (`reproducible-build.sh`
   automates the double build + comparison.)
2. Compare your PCR0 against the **canonical PCR0** published in that doc.
3. Compare the PCR0 inside a running enclave's NSM attestation (any bundle's
   `proof.attestation`) against the same value.

A three-way match — your build == doc == live attestation — proves the running enclave is
compiled from exactly this source, with nothing smuggled in.

## What it does *not* guarantee

Integrity / authenticity, **not** confidentiality: the relay node still transiently handles
plaintext (it is just never persisted). See [`../docs/TEE.md`](../docs/TEE.md) §2.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at
your option (`SPDX-License-Identifier: MIT OR Apache-2.0`). Third-party attribution: see
[`NOTICE`](NOTICE).
