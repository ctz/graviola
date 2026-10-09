use std::borrow::Cow;
use std::sync::Arc;

use rustls::crypto::kx::SupportedKxGroup;
use rustls::crypto::{Credentials, CryptoProvider, Identity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{
    ClientConfig, Connection, HandshakeKind, RootCertStore, ServerConfig, ServerConnection,
    Tls12CipherSuite, Tls13CipherSuite, VecInput,
};

#[test]
fn all_suites() {
    let _ = env_logger::try_init();

    for key_type in KeyType::ALL {
        test_tls13_suite(rustls_graviola::suites::TLS13_AES_256_GCM_SHA384, *key_type);
        test_tls13_suite(rustls_graviola::suites::TLS13_AES_128_GCM_SHA256, *key_type);
        test_tls13_suite(
            rustls_graviola::suites::TLS13_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
        test_keys_match(&rustls_graviola::default_provider(), *key_type);
    }

    for key_type in KeyType::RSA {
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            *key_type,
        );
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            *key_type,
        );
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
    }

    for key_type in KeyType::ECDSA {
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            *key_type,
        );
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            *key_type,
        );
        test_tls12_suite(
            rustls_graviola::suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            *key_type,
        );
    }
}

#[test]
fn all_key_exchanges() {
    // X25519MLKEM768 not supported by *ring*
    for other in [OtherProvider::BaselineAwsLcRs, OtherProvider::SelfTest] {
        test_key_exchange(rustls_graviola::kx::X25519MLKEM768, other, KeyType::Rsa2048);
    }

    for other in OtherProvider::OTHERS {
        test_key_exchange(&rustls_graviola::kx::X25519, *other, KeyType::Rsa2048);
        test_key_exchange(&rustls_graviola::kx::P256, *other, KeyType::Rsa2048);
        test_key_exchange(&rustls_graviola::kx::P384, *other, KeyType::Rsa2048);
    }
}

fn test_key_exchange(kx: &'static dyn SupportedKxGroup, other: OtherProvider, key_type: KeyType) {
    let provider: Arc<_> = CryptoProvider {
        kx_groups: Cow::Owned(vec![kx]),
        ..rustls_graviola::default_provider()
    }
    .into();
    test_client(provider.clone(), other, key_type);
    test_server(provider, other, key_type);
}

fn test_tls13_suite(suite: &'static Tls13CipherSuite, key_type: KeyType) {
    test_provider(
        CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![]),
            tls13_cipher_suites: Cow::Owned(vec![suite]),
            ..rustls_graviola::default_provider()
        },
        key_type,
    );
}

fn test_tls12_suite(suite: &'static Tls12CipherSuite, key_type: KeyType) {
    test_provider(
        CryptoProvider {
            tls12_cipher_suites: Cow::Owned(vec![suite]),
            tls13_cipher_suites: Cow::Owned(vec![]),
            ..rustls_graviola::default_provider()
        },
        key_type,
    );
}

fn test_provider(provider: CryptoProvider, key_type: KeyType) {
    let provider = Arc::new(provider);
    for other in OtherProvider::OTHERS {
        test_client(provider.clone(), *other, key_type);
        test_server(provider.clone(), *other, key_type);
    }
}

fn test_client(provider: Arc<CryptoProvider>, other: OtherProvider, key_type: KeyType) {
    let server_config = server_config(other.into_provider(), key_type);
    let client_config = client_config(provider.clone(), key_type);

    assert!(matches!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest
    ));
    println!("FULL: client with {provider:?} {key_type:?} OK");

    assert_eq!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Resumed
    );
    println!("RESUMED: client with {provider:?} {key_type:?} OK");
}

fn test_server(provider: Arc<CryptoProvider>, other: OtherProvider, key_type: KeyType) {
    let server_config = server_config(provider.clone(), key_type);
    let client_config = client_config(other.into_provider(), key_type);

    assert!(matches!(
        exercise(client_config.clone(), server_config.clone()),
        HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest
    ));
    println!("FULL: server with {provider:?} {key_type:?} OK");

    assert_eq!(
        exercise(client_config, server_config),
        HandshakeKind::Resumed
    );
    println!("RESUMED: server with {provider:?} {key_type:?} OK");
}

fn server_config(provider: Arc<CryptoProvider>, key_type: KeyType) -> Arc<ServerConfig> {
    ServerConfig::builder(provider)
        .with_no_client_auth()
        .with_single_cert(key_type.identity(), key_type.key())
        .unwrap()
        .into()
}

fn client_config(provider: Arc<CryptoProvider>, key_type: KeyType) -> Arc<ClientConfig> {
    ClientConfig::builder(provider)
        .with_root_certificates(key_type.ca_certs())
        .with_no_client_auth()
        .unwrap()
        .into()
}

fn exercise(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>) -> HandshakeKind {
    let (mut client_input, mut client_output, mut client_received) =
        (VecInput::default(), Vec::new(), Vec::new());
    let (mut server_input, mut server_output, mut server_received) =
        (VecInput::default(), Vec::new(), Vec::new());

    let mut client = client_config
        .connect("localhost".try_into().unwrap())
        .build(&mut client_output)
        .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();

    while client.is_handshaking() || server.is_handshaking() {
        transfer(&mut client_output, &mut server_input);
        server
            .read_tls(&mut server_input, &mut server_output)
            .handle_all(&mut server_received)
            .unwrap();

        transfer(&mut server_output, &mut client_input);
        client
            .read_tls(&mut client_input, &mut client_output)
            .handle_all(&mut client_received)
            .unwrap();
    }

    client
        .write(b"hello world".into(), &mut client_output)
        .unwrap();
    client.send_close_notify(&mut client_output).unwrap();
    transfer(&mut client_output, &mut server_input);
    server
        .read_tls(&mut server_input, &mut server_output)
        .handle_all(&mut server_received)
        .unwrap();
    assert_eq!(server_received, b"hello world");

    server.write(b"goodbye".into(), &mut server_output).unwrap();
    transfer(&mut server_output, &mut client_input);
    client
        .read_tls(&mut client_input, &mut client_output)
        .handle_all(&mut client_received)
        .unwrap();
    assert_eq!(client_received, b"goodbye");

    server.handshake_kind().unwrap()
}

fn transfer(output: &mut Vec<u8>, input: &mut VecInput) {
    let mut offs = 0;
    while offs < output.len() {
        offs += input.read(&mut &output[offs..]).unwrap();
    }
    output.clear();
}

fn test_keys_match(provider: &CryptoProvider, key_type: KeyType) {
    Credentials::from_der(key_type.identity(), key_type.key(), provider).unwrap();
}

#[derive(Clone, Copy, Debug)]
enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
}

impl KeyType {
    const ALL: &[Self] = &[
        Self::Rsa2048,
        Self::Rsa3072,
        Self::Rsa4096,
        Self::EcdsaP256,
        Self::EcdsaP384,
        Self::Ed25519,
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
            Self::Ed25519 => "ed25519",
        }
    }

    fn identity(self) -> Arc<Identity<'static>> {
        let chain =
            CertificateDer::pem_file_iter(format!("tests/keys/{}/end.fullchain", self.slug()))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        Arc::new(Identity::from_cert_chain(chain).unwrap())
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
    BaselineRing,
    BaselineAwsLcRs,
    SelfTest,
}

impl OtherProvider {
    fn into_provider(self) -> Arc<CryptoProvider> {
        match self {
            Self::BaselineRing => rustls_ring::DEFAULT_PROVIDER.into(),
            Self::BaselineAwsLcRs => rustls_aws_lc_rs::DEFAULT_PROVIDER.into(),
            Self::SelfTest => rustls_graviola::default_provider().into(),
        }
    }

    const OTHERS: &[Self] = &[Self::BaselineRing, Self::BaselineAwsLcRs];
}
