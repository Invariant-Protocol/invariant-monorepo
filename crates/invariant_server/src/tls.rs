// crates/invariant_server/src/tls.rs
/*
 * Copyright (c) 2026 Invariant Protocol.
 *
 * This source code is licensed under the Business Source License (BSL 1.1) 
 * found in the LICENSE.md file in the root directory of this source tree.
 */

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

fn load_certs_and_key(cert_path: &str, key_path: &str) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert_file = File::open(cert_path).expect("Failed to open server cert");
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|result| result.expect("Failed to parse certificate").into_owned())
        .collect();

    let key_file = File::open(key_path).expect("Failed to open server key");
    let mut key_reader = BufReader::new(key_file);
    let key_item = rustls_pemfile::read_one(&mut key_reader)
        .expect("Failed to read private key file")
        .expect("Private key file is empty");

    let key: PrivateKeyDer<'static> = match key_item {
        rustls_pemfile::Item::Pkcs1Key(k) => k.into(),
        rustls_pemfile::Item::Pkcs8Key(k) => k.into(),
        rustls_pemfile::Item::Sec1Key(k) => k.into(),
        _ => panic!("Unsupported private key format"),
    };
    
    (certs, key)
}

/// 🛡️ THE FORTRESS (Port 8443)
/// Strictly enforces client certificate authentication at the transport layer.
pub fn build_mtls_config(cert_path: &str, key_path: &str, ca_path: &str) -> ServerConfig {
    let (certs, key) = load_certs_and_key(cert_path, key_path);

    let ca_file = File::open(ca_path).expect("Failed to open CA cert");
    let mut ca_reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();

    for cert in rustls_pemfile::certs(&mut ca_reader) {
        root_store.add(cert.expect("Failed to parse CA certificate")).expect("Failed to add CA");
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .expect("Failed to build client cert verifier");

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("Failed to build ServerConfig")
}

/// 🛡️ THE ENROLLMENT GATE (Port 8444)
/// Standard TLS. Exposes the /provision endpoints to allow first-boot SDKs 
/// to prove hardware identity and retrieve an mTLS certificate.
pub fn build_standard_tls_config(cert_path: &str, key_path: &str) -> ServerConfig {
    let (certs, key) = load_certs_and_key(cert_path, key_path);

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build ServerConfig")
}