// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stack {
    Rustls,
    Boring,
    OpenSsl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GreasePolicy {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtOrder {
    Fixed,
    PermutePerSession,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertPolicy {
    WebpkiRoots,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct H2Settings {
    pub settings: Vec<(u16, u32)>,
    pub window_update: u32,
    pub pseudo_header_order: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsProfile {
    pub spec_id: u32,
    pub issued_at: u64,
    pub label: String,
    pub stack: Stack,

    pub cipher_list: String,
    pub sigalgs: Vec<String>,
    pub groups: Vec<String>,
    pub alpn: Vec<String>,
    pub grease: GreasePolicy,
    pub ext_order: ExtOrder,

    pub min_negotiated: TlsVersion,
    pub cert_policy: CertPolicy,

    pub h2: Option<H2Settings>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Eof,
    Utf8,
    BadTag(&'static str),
    Trailing,
}


fn put_len(o: &mut Vec<u8>, n: usize) {
    o.extend_from_slice(&(n as u32).to_be_bytes());
}
fn put_bytes(o: &mut Vec<u8>, b: &[u8]) {
    put_len(o, b.len());
    o.extend_from_slice(b);
}
fn put_str(o: &mut Vec<u8>, s: &str) {
    put_bytes(o, s.as_bytes());
}
fn put_strs(o: &mut Vec<u8>, v: &[String]) {
    put_len(o, v.len());
    for s in v {
        put_str(o, s);
    }
}

pub fn canonical_encode(s: &TlsProfile) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&s.spec_id.to_be_bytes());
    o.extend_from_slice(&s.issued_at.to_be_bytes());
    put_str(&mut o, &s.label);
    o.push(match s.stack {
        Stack::Rustls => 0,
        Stack::Boring => 1,
        Stack::OpenSsl => 2,
    });
    put_str(&mut o, &s.cipher_list);
    put_strs(&mut o, &s.sigalgs);
    put_strs(&mut o, &s.groups);
    put_strs(&mut o, &s.alpn);
    o.push(match s.grease {
        GreasePolicy::Disabled => 0,
        GreasePolicy::Enabled => 1,
    });
    o.push(match s.ext_order {
        ExtOrder::Fixed => 0,
        ExtOrder::PermutePerSession => 1,
    });
    o.push(match s.min_negotiated {
        TlsVersion::Tls12 => 0,
        TlsVersion::Tls13 => 1,
    });
    match &s.cert_policy {
        CertPolicy::WebpkiRoots => o.push(0),
    }
    match &s.h2 {
        None => o.push(0),
        Some(h2) => {
            o.push(1);
            put_len(&mut o, h2.settings.len());
            for (id, val) in &h2.settings {
                o.extend_from_slice(&id.to_be_bytes());
                o.extend_from_slice(&val.to_be_bytes());
            }
            o.extend_from_slice(&h2.window_update.to_be_bytes());
            put_strs(&mut o, &h2.pseudo_header_order);
        }
    }
    o
}


struct Dec<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Dec<'a> {
    fn new(b: &'a [u8]) -> Self {
        Dec { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.i.checked_add(n).ok_or(DecodeError::Eof)?;
        if end > self.b.len() {
            return Err(DecodeError::Eof);
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    fn len(&mut self) -> Result<usize, DecodeError> {
        Ok(self.u32()? as usize)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }
    fn s(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError::Utf8)
    }
    fn strs(&mut self) -> Result<Vec<String>, DecodeError> {
        let n = self.len()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(self.s()?);
        }
        Ok(v)
    }
}

pub fn decode(b: &[u8]) -> Result<TlsProfile, DecodeError> {
    let mut d = Dec::new(b);
    let spec_id = d.u32()?;
    let issued_at = d.u64()?;
    let label = d.s()?;
    let stack = match d.u8()? {
        0 => Stack::Rustls,
        1 => Stack::Boring,
        2 => Stack::OpenSsl,
        _ => return Err(DecodeError::BadTag("stack")),
    };
    let cipher_list = d.s()?;
    let sigalgs = d.strs()?;
    let groups = d.strs()?;
    let alpn = d.strs()?;
    let grease = match d.u8()? {
        0 => GreasePolicy::Disabled,
        1 => GreasePolicy::Enabled,
        _ => return Err(DecodeError::BadTag("grease")),
    };
    let ext_order = match d.u8()? {
        0 => ExtOrder::Fixed,
        1 => ExtOrder::PermutePerSession,
        _ => return Err(DecodeError::BadTag("ext_order")),
    };
    let min_negotiated = match d.u8()? {
        0 => TlsVersion::Tls12,
        1 => TlsVersion::Tls13,
        _ => return Err(DecodeError::BadTag("tls_version")),
    };
    let cert_policy = match d.u8()? {
        0 => CertPolicy::WebpkiRoots,
        _ => return Err(DecodeError::BadTag("cert_policy")),
    };
    let h2 = match d.u8()? {
        0 => None,
        1 => {
            let sn = d.len()?;
            let mut settings = Vec::new();
            for _ in 0..sn {
                settings.push((d.u16()?, d.u32()?));
            }
            let window_update = d.u32()?;
            let pseudo_header_order = d.strs()?;
            Some(H2Settings {
                settings,
                window_update,
                pseudo_header_order,
            })
        }
        _ => return Err(DecodeError::BadTag("h2")),
    };
    if d.i != d.b.len() {
        return Err(DecodeError::Trailing);
    }
    Ok(TlsProfile {
        spec_id,
        issued_at,
        label,
        stack,
        cipher_list,
        sigalgs,
        groups,
        alpn,
        grease,
        ext_order,
        min_negotiated,
        cert_policy,
        h2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TlsProfile {
        TlsProfile {
            spec_id: 1,
            issued_at: 0,
            label: "example-client".into(),
            stack: Stack::Rustls,
            cipher_list: String::new(),
            sigalgs: vec![],
            groups: vec!["X25519".into(), "P-256".into()],
            alpn: vec!["http/1.1".into()],
            grease: GreasePolicy::Disabled,
            ext_order: ExtOrder::Fixed,
            min_negotiated: TlsVersion::Tls12,
            cert_policy: CertPolicy::WebpkiRoots,
            h2: None,
        }
    }

    #[test]
    fn encode_roundtrips_and_is_deterministic() {
        let s = sample();
        let enc = canonical_encode(&s);
        assert_eq!(decode(&enc).unwrap(), s, "decode∘encode == identity");
        assert_eq!(
            canonical_encode(&decode(&enc).unwrap()),
            enc,
            "encode 确定性"
        );
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let mut enc = canonical_encode(&sample());
        enc.push(0xff);
        assert_eq!(decode(&enc), Err(DecodeError::Trailing));
    }

    #[test]
    fn decode_rejects_huge_length_prefix_without_oom() {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u64.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.push(1);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(decode(&b), Err(DecodeError::Eof));
    }

    #[test]
    fn h2_variant_roundtrips() {
        let mut s = sample();
        s.h2 = Some(H2Settings {
            settings: vec![(1, 65536), (4, 6291456)],
            window_update: 15663105,
            pseudo_header_order: vec![":method".into(), ":authority".into(), ":scheme".into(), ":path".into()],
        });
        let enc = canonical_encode(&s);
        assert_eq!(decode(&enc).unwrap(), s);
    }
}
