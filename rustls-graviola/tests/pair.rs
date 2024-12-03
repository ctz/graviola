use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::ring::default_provider as baseline;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

#[test]
fn all_suites() {
    for key_type in KeyType::ALL {
        test_suite(rustls_graviola::suites::TLS13_AES_256_GCM_SHA384, *key_type);
        test_suite(rustls_graviola::suites::TLS13_AES_128_GCM_SHA256, *key_type);
        test_suite(
            rustls_graviola::suites::TLS13_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
    }

    for key_type in KeyType::RSA {
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            *key_type,
        );
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            *key_type,
        );
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
    }

    for key_type in KeyType::ECDSA {
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            *key_type,
        );
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            *key_type,
        );
        test_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
    }
}

#[test]
fn all_key_exchanges() {
    test_key_exchange(&rustls_graviola::kx::X25519, KeyType::Rsa2048);
    test_key_exchange(&rustls_graviola::kx::P256, KeyType::Rsa2048);
    test_key_exchange(&rustls_graviola::kx::P384, KeyType::Rsa2048);
}

fn test_key_exchange(kx: &'static dyn SupportedKxGroup, key_type: KeyType) {
    let provider: Arc<_> = CryptoProvider {
        kx_groups: vec![kx],
        ..rustls_graviola::default_provider()
    }
    .into();
    test_client(provider.clone(), key_type);
    test_server(provider, key_type);
}

fn test_suite(suite: rustls::SupportedCipherSuite, key_type: KeyType) {
    let provider: Arc<_> = CryptoProvider {
        cipher_suites: vec![suite],
        ..rustls_graviola::default_provider()
    }
    .into();
    test_client(provider.clone(), key_type);
    test_server(provider, key_type);
}

fn test_client(provider: Arc<CryptoProvider>, key_type: KeyType) {
    let mut server = server_with(baseline().into(), key_type);
    let mut client = client_with(provider.clone(), key_type);

    exercise(&mut client, &mut server);
    println!("client with {:?} {:?} OK", provider, key_type);
}
fn test_server(provider: Arc<CryptoProvider>, key_type: KeyType) {
    let mut server = server_with(provider.clone(), key_type);
    let mut client = client_with(baseline().into(), key_type);

    exercise(&mut client, &mut server);
    println!("server with {:?} {:?} OK", provider, key_type);
}
fn server_with(provider: Arc<CryptoProvider>, key_type: KeyType) -> ServerConnection {
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(key_type.cert_chain(), key_type.key())
        .unwrap();

    ServerConnection::new(server_config.into()).unwrap()
}

fn client_with(provider: Arc<CryptoProvider>, key_type: KeyType) -> ClientConnection {
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(key_type.ca_certs())
        .with_no_client_auth();

    ClientConnection::new(client_config.into(), "localhost".try_into().unwrap()).unwrap()
}

fn exercise(client: &mut ClientConnection, server: &mut ServerConnection) {
    while client.is_handshaking() && server.is_handshaking() {
        let mut buf = [0u8; 1024];
        let wr = client.write_tls(&mut &mut buf[..]).unwrap();
        server.read_tls(&mut &buf[..wr]).unwrap();
        server.process_new_packets().unwrap();

        let wr = server.write_tls(&mut &mut buf[..]).unwrap();
        client.read_tls(&mut &buf[..wr]).unwrap();
        client.process_new_packets().unwrap();
    }

    let _ = client.writer().write(b"hello world").unwrap();
    client.send_close_notify();
    let mut buf = [0u8; 1024];
    let wr = client.write_tls(&mut &mut buf[..]).unwrap();
    server.read_tls(&mut &buf[..wr]).unwrap();
    server.process_new_packets().unwrap();

    let mut out = vec![];
    server.reader().read_to_end(&mut out).unwrap();
    assert_eq!(out, b"hello world");
}

#[derive(Clone, Copy, Debug)]
enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
}

impl KeyType {
    const ALL: &[Self] = &[
        Self::Rsa2048,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::EcdsaP256,
        Self::EcdsaP384,
    ];
    const RSA: &[Self] = &[Self::Rsa2048, Self::Rsa3072, Self::Rsa4096];
    const ECDSA: &[Self] = &[Self::EcdsaP256, Self::EcdsaP384];

    fn slug(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa-2048",
            Self::Rsa3072 => "rsa-3072",
            Self::Rsa4096 => "rsa-4096",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
        }
    }

    fn cert_chain(self) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(format!("tests/keys/{}/end.fullchain", self.slug()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn key(self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(format!("tests/keys/{}/end.key", self.slug())).unwrap()
    }

    fn ca_certs(self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(
                CertificateDer::from_pem_file(format!("tests/keys/{}/ca.cert", self.slug()))
                    .unwrap(),
            )
            .unwrap();
        roots.into()
    }
}
