import { describe, expect, it } from 'vitest';
import { verifyAttestationDoc } from './verify-attestation-cose.mjs';

describe('verify-attestation-cose bounded CBOR decoder', () => {
  it('supports bounded indefinite-length CBOR and then validates the COSE shape', () => {
    expect(() => verifyAttestationDoc(Buffer.from([0x9f, 0xff]))).toThrow(/invalid COSE_Sign1/);
  });

  it('rejects an unexpected CBOR break marker', () => {
    expect(() => verifyAttestationDoc(Buffer.from([0xff]))).toThrow(/unexpected break/);
  });

  it('rejects unterminated indefinite-length containers', () => {
    expect(() => verifyAttestationDoc(Buffer.from([0x9f]))).toThrow(/truncated item/);
  });

  it('rejects declared container lengths above the hard cap', () => {
    expect(() => verifyAttestationDoc(Buffer.from([0x99, 0x04, 0x01]))).toThrow(/array too large/);
  });

  it('rejects declared byte strings above the hard cap', () => {
    expect(() => verifyAttestationDoc(Buffer.from([0x5a, 0xff, 0xff, 0xff, 0xff]))).toThrow(/byte string too large/);
  });

  it('rejects excessively nested tags', () => {
    expect(() => verifyAttestationDoc(Buffer.from([...Array(40).fill(0xc0), 0xf6]))).toThrow(/nesting too deep/);
  });
});
