// SPDX-License-Identifier: MIT OR Apache-2.0
// Grok Build CLI 0.2.101 TLS：rustls 0.23.37 + aws-lc-rs，ALPN=h2,http/1.1。
// 独立于既有 ring 兜底，避免为一个画像改变所有无画像请求的 ClientHello。

use attest::tls_profile::{CertPolicy, ExtOrder, GreasePolicy, TlsProfile, TlsVersion};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, SignatureScheme, StreamOwned};
use std::sync::{Arc, OnceLock};
use vsock::VsockStream;

pub fn connect(
    profile: &TlsProfile,
    sock: VsockStream,
    sni: &str,
) -> Result<StreamOwned<ClientConnection, VsockStream>, String> {
    validate_shape(profile)?;
    let mut roots = RootCertStore::empty();
    match profile.cert_policy {
        CertPolicy::WebpkiRoots => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Grok 0.2.101 used classical groups only. Starting with 1.0.24
    // (spec #11), the official CLI enables X25519MLKEM768 first.
    provider.kx_groups = if profile.spec_id == 11 {
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ]
    } else {
        vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ]
    };
    provider.signature_verification_algorithms = grok_signature_algorithms(profile.spec_id == 11);
    let versions: &[&'static rustls::SupportedProtocolVersion] = match profile.min_negotiated {
        TlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
        TlsVersion::Tls13 => &[&rustls::version::TLS13],
    };
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| format!("rustls/aws-lc protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = profile.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let server_name =
        ServerName::try_from(sni.to_owned()).map_err(|e| format!("SNI 非法: {e:?}"))?;
    let conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("rustls/aws-lc TLS 初始化失败: {e}"))?;
    Ok(StreamOwned::new(conn, sock))
}

fn grok_signature_algorithms(include_p521: bool) -> rustls::crypto::WebPkiSupportedAlgorithms {
    static LEGACY: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
    static CURRENT: OnceLock<rustls::crypto::WebPkiSupportedAlgorithms> = OnceLock::new();
    let slot = if include_p521 { &CURRENT } else { &LEGACY };
    *slot.get_or_init(|| {
        let base = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let mapping = base
            .mapping
            .iter()
            .copied()
            .filter(|(scheme, _)| include_p521 || *scheme != SignatureScheme::ECDSA_NISTP521_SHA512)
            .collect::<Vec<_>>();
        rustls::crypto::WebPkiSupportedAlgorithms {
            all: base.all,
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}

fn validate_shape(profile: &TlsProfile) -> Result<(), String> {
    if !profile.cipher_list.is_empty() || !profile.sigalgs.is_empty() || !profile.groups.is_empty()
    {
        return Err("rustls/aws-lc 画像只允许固定 provider 默认 cipher/sigalg/group".into());
    }
    if profile.grease != GreasePolicy::Disabled || profile.ext_order != ExtOrder::PermutePerSession
    {
        return Err("Grok rustls/aws-lc 画像要求 GREASE=Disabled + 每连接扩展随机序".into());
    }
    Ok(())
}
