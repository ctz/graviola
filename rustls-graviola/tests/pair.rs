use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::ring::default_provider as baseline;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, RootCertStore, ServerConfig, ServerConnection,
};

#[test]
fn all_suites() {
    let _ = env_logger::try_init();

    for key_type in KeyType::ALL {
        test_suite(rustls_graviola::suites::TLS13_AES_256_GCM_SHA384, *key_type);
        test_suite(rustls_graviola::suites::TLS13_AES_128_GCM_SHA256, *key_type);
        test_suite(
            rustls_graviola::suites::TLS13_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
        test_keys_match(&rustls_graviola::default_provider(), *key_type);
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
    test_key_exchange(
        rustls_graviola::kx::X25519MLKEM768,
        OtherProvider::SelfTest, // not supported by *ring*
        KeyType::Rsa2048,
    );
    test_key_exchange(
        &rustls_graviola::kx::X25519,
        OtherProvider::Baseline,
        KeyType::Rsa2048,
    );
    test_key_exchange(
        &rustls_graviola::kx::P256,
        OtherProvider::Baseline,
        KeyType::Rsa2048,
    );
    test_key_exchange(
        &rustls_graviola::kx::P384,
        OtherProvider::Baseline,
        KeyType::Rsa2048,
    );
}

fn test_key_exchange(kx: &'static dyn SupportedKxGroup, other: OtherProvider, key_type: KeyType) {
    let provider: Arc<_> = CryptoProvider {
        kx_groups: vec![kx],
        ..rustls_graviola::default_provider()
    }
    .into();
    test_client(provider.clone(), other, key_type);
    test_server(provider, other, key_type);
}

fn test_suite(suite: rustls::SupportedCipherSuite, key_type: KeyType) {
    let provider: Arc<_> = CryptoProvider {
        cipher_suites: vec![suite],
        ..rustls_graviola::default_provider()
    }
    .into();
    test_client(provider.clone(), OtherProvider::Baseline, key_type);
    test_server(provider, OtherProvider::Baseline, key_type);
}

fn test_client(provider: Arc<CryptoProvider>, other: OtherProvider, key_type: KeyType) {
    let server_config = server_config(other.into_provider(), key_type);
    let client_config = client_config(provider.clone(), key_type);

    assert!(matches!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest
    ));
    println!("FULL: client with {:?} {:?} OK", provider, key_type);

    assert_eq!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Resumed
    );
    println!("RESUMED: client with {:?} {:?} OK", provider, key_type);
}

fn test_server(provider: Arc<CryptoProvider>, other: OtherProvider, key_type: KeyType) {
    let server_config = server_config(provider.clone(), key_type);
    let client_config = client_config(other.into_provider(), key_type);

    assert!(matches!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest
    ));
    println!("FULL: server with {:?} {:?} OK", provider, key_type);

    assert_eq!(
        exercise(client_config, server_config),
        HandshakeKind::Resumed
    );
    println!("RESUMED: server with {:?} {:?} OK", provider, key_type);
}

fn server_config(provider: Arc<CryptoProvider>, key_type: KeyType) -> Arc<ServerConfig> {
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(key_type.cert_chain(), key_type.key())
        .unwrap()
        .into()
}

fn client_config(provider: Arc<CryptoProvider>, key_type: KeyType) -> Arc<ClientConfig> {
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(key_type.ca_certs())
        .with_no_client_auth()
        .into()
}

fn exercise(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>) -> HandshakeKind {
    let mut client = ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

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

    let _ = server.writer().write(b"goodbye").unwrap();
    let wr = server.write_tls(&mut &mut buf[..]).unwrap();
    client.read_tls(&mut &buf[..wr]).unwrap();
    client.process_new_packets().unwrap();

    server.handshake_kind().unwrap()
}

fn test_keys_match(provider: &CryptoProvider, key_type: KeyType) {
    CertifiedKey::from_der(key_type.cert_chain(), key_type.key(), provider)
        .unwrap()
        .keys_match()
        .unwrap();
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

#[derive(Copy, Clone, Debug)]
enum OtherProvider {
    Baseline,
    SelfTest,
}

impl OtherProvider {
    fn into_provider(self) -> Arc<CryptoProvider> {
        match self {
            Self::Baseline => baseline().into(),
            Self::SelfTest => rustls_graviola::default_provider().into(),
        }
    }
}
