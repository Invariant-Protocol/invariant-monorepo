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

/// Constructs a Rustls ServerConfig that strictly enforces client certificate authentication.
pub fn build_tls_config(cert_path: &str, key_path: &str, ca_path: &str) -> ServerConfig {
    // 1. Load Server Certificate
    let cert_file = File::open(cert_path).expect("Failed to open server cert");
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|result| result.expect("Failed to parse certificate").into_owned())
        .collect();

    // 2. Load Server Private Key
    let key_file = File::open(key_path).expect("Failed to open server key");
    let mut key_reader = BufReader::new(key_file);
    
    // rustls-pemfile v2 returns an iterator over items. We extract the first valid private key.
    let key_item = rustls_pemfile::read_one(&mut key_reader)
        .expect("Failed to read private key file")
        .expect("Private key file is empty");

    let key: PrivateKeyDer<'static> = match key_item {
        rustls_pemfile::Item::Pkcs1Key(k) => k.into(),
        rustls_pemfile::Item::Pkcs8Key(k) => k.into(),
        rustls_pemfile::Item::Sec1Key(k) => k.into(),
        _ => panic!("Unsupported private key format"),
    };

    // 3. Load Client CA Trust Anchors
    let ca_file = File::open(ca_path).expect("Failed to open CA cert");
    let mut ca_reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();

    for cert in rustls_pemfile::certs(&mut ca_reader) {
        root_store.add(cert.expect("Failed to parse CA certificate")).expect("Failed to add CA");
    }

    // 4. Enforce Client Authentication via WebPkiClientVerifier
    // This configures the server to drop connections missing a valid cert signed by the root_store
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .expect("Failed to build client cert verifier");

    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .expect("Failed to build ServerConfig")
}