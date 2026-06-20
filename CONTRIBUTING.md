# Contributing

Thanks for your interest in proof-of-observation. This repository is the measured enclave plus
its client-side verifier — nothing else.

## Layout

```text
enclave/    the measured Rust enclave (the TCB that PCR0 measures) + reproducible build
verifier/   the proof verifier (TypeScript / JS) + golden vectors
docs/       architecture, the v2 signing spec, the reproducible-build procedure, browser verifier
```

## Local development

Enclave (Rust):

```bash
cd enclave
cargo test            # unit + golden-vector tests
```

> The full reproducible **PCR0** build requires an `aarch64` host with Docker and the AWS Nitro
> CLI — see [`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md). The unit tests
> run on any platform.

Verifier (Node 20+):

```bash
cd verifier
npm ci
npm test              # Vitest
```

CI runs both on every pull request.

## Trust boundary (please preserve)

This repository backs a verifiable-integrity claim, so a few invariants must hold:

- **Generic examples only.** Tests, vectors, and docs use placeholder hosts (`api.example.com`)
  and example payloads — do not hardcode a specific upstream provider, real credentials, or
  production infrastructure (IPs, internal hostnames).
- **No secrets in logs.** Never log credentials, authorization headers, or plaintext bodies.
- **The signing statement is a wire contract.** `enclave/src/main.rs` (`build_v2_statement`),
  `verifier/signing.ts` (`buildV2Statement`), and the browser verifier must stay **byte-identical**;
  the golden vectors enforce this. Changing the layout is a breaking change — it moves PCR0 and
  requires re-issuing verifiers.
- **Integrity, not confidentiality.** Don't claim the enclave hides plaintext from the relay; it
  does not (see [`docs/TEE.md`](docs/TEE.md) §2).

## Pull requests

- Keep changes focused; update tests and docs for any behavior change.
- The measured enclave source is **byte-sensitive** — even a comment moves PCR0. Read
  [`docs/tee-reproducible-build.md`](docs/tee-reproducible-build.md) before touching `enclave/src/**`.
- Security issues: do not open a public issue — see [`SECURITY.md`](SECURITY.md).
