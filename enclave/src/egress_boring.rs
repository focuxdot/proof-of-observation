// SPDX-License-Identifier: MIT OR Apache-2.0

use attest::tls_profile::{CertPolicy, ExtOrder, GreasePolicy, TlsProfile, TlsVersion};
use btls::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use btls::x509::X509;
use vsock::VsockStream;

pub fn connect(
    profile: &TlsProfile,
    sock: VsockStream,
    sni: &str,
    seed: Option<&[u8]>,
) -> Result<SslStream<VsockStream>, String> {
    let _ = seed;
    let mut b =
        SslConnector::builder(SslMethod::tls()).map_err(|e| format!("btls builder: {}", e))?;

    b.set_cipher_list(&profile.cipher_list)
        .map_err(|e| format!("set_cipher_list: {}", e))?;
    if !profile.groups.is_empty() {
        b.set_curves_list(&profile.groups.join(":"))
            .map_err(|e| format!("set_curves_list: {}", e))?;
    }
    if !profile.sigalgs.is_empty() {
        b.set_sigalgs_list(&profile.sigalgs.join(":"))
            .map_err(|e| format!("set_sigalgs_list: {}", e))?;
    }
    b.set_alpn_protos(&alpn_wire(&profile.alpn))
        .map_err(|e| format!("set_alpn_protos: {}", e))?;
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();
    match profile.grease {
        GreasePolicy::Disabled => {}
        GreasePolicy::Enabled => return Err("grease=Enabled 渲染未实现".into()),
    }
    match profile.ext_order {
        ExtOrder::Fixed => {}
        ExtOrder::PermutePerSession => return Err("ext_order=PermutePerSession 渲染未实现".into()),
    }

    let floor = match profile.min_negotiated {
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    };
    b.set_min_proto_version(Some(floor))
        .map_err(|e| format!("set_min_proto_version: {}", e))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3)).ok();

    match &profile.cert_policy {
        CertPolicy::WebpkiRoots => {
            b.set_verify(SslVerifyMode::PEER);
            let pem: &[u8] = include_bytes!("ca-bundle.pem");
            let store = b.cert_store_mut();
            for cert in X509::stack_from_pem(pem).map_err(|e| format!("解析 ca-bundle: {}", e))? {
                store
                    .add_cert(cert)
                    .map_err(|e| format!("加 CA root: {}", e))?;
            }
        }
    }

    let cfg = b
        .build()
        .configure()
        .map_err(|e| format!("btls configure: {}", e))?;
    cfg.connect(sni, sock)
        .map_err(|e| format!("btls TLS 握手失败: {}", e))
}

fn alpn_wire(protos: &[String]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in protos {
        v.push(p.len() as u8);
        v.extend_from_slice(p.as_bytes());
    }
    v
}
