//! Bulk encryption and decryption throughput, over every supported
//! protocol version and cipher suite.
//!
//! Each benchmark runs a handshake between an in-memory client and server
//! (both using `rustls-graviola`), and then measures transferring
//! application data from the client to the server.  "encrypt" measures
//! `Connection::write()` on the client.  "decrypt" measures the server
//! accepting the resulting TLS data and yielding its plaintext.

use std::borrow::Cow;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustls::crypto::{CipherSuite, CryptoProvider, Identity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{
    ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection,
    Tls12CipherSuite, Tls13CipherSuite, VecInput,
};
use rustls_graviola::suites;

/// Plaintext sizes written per iteration: one full record, and a bulk transfer.
const SIZES: &[(usize, &str)] = &[(16 * 1024, "16KB"), (1024 * 1024, "1MB")];

fn bulk(c: &mut Criterion) {
    for suite in all_suites() {
        let (client_config, server_config) = configs(suite);
        let name = suite.name();

        // check the configs negotiate what we expect
        let pair = Pair::new(&client_config, &server_config);
        assert_eq!(
            pair.server.negotiated_cipher_suite().map(|s| s.suite()),
            Some(suite.id())
        );

        let mut group = c.benchmark_group(format!("bulk/{name}"));
        for &(size, size_name) in SIZES {
            let plain = vec![0u8; size];
            group.throughput(Throughput::Bytes(size as u64));

            group.bench_function(BenchmarkId::new("encrypt", size_name), |b| {
                b.iter_custom(|iters| {
                    let mut pair = Pair::new(&client_config, &server_config);
                    let mut tls = Vec::new();

                    let start = Instant::now();
                    for _ in 0..iters {
                        pair.client
                            .write(black_box(&plain).into(), &mut tls)
                            .unwrap();
                        black_box(&tls);
                        tls.clear();
                    }
                    start.elapsed()
                });
            });

            group.bench_function(BenchmarkId::new("decrypt", size_name), |b| {
                b.iter_custom(|iters| {
                    let mut pair = Pair::new(&client_config, &server_config);
                    let mut elapsed = Duration::ZERO;

                    for _ in 0..iters {
                        pair.client
                            .write((&plain).into(), &mut pair.client_tls)
                            .unwrap();

                        let start = Instant::now();
                        let received = pair.client_to_server();
                        elapsed += start.elapsed();

                        assert_eq!(received, size);
                    }
                    elapsed
                });
            });
        }
        group.finish();
    }
}

#[derive(Clone, Copy)]
enum Suite {
    Tls12(&'static Tls12CipherSuite),
    Tls13(&'static Tls13CipherSuite),
}

impl Suite {
    fn id(self) -> CipherSuite {
        match self {
            Self::Tls12(s) => s.common.suite,
            Self::Tls13(s) => s.common.suite,
        }
    }

    fn name(self) -> String {
        let version = match self {
            Self::Tls12(_) => "TLS1.2",
            Self::Tls13(_) => "TLS1.3",
        };
        format!("{version}/{:?}", self.id())
    }
}

fn all_suites() -> impl Iterator<Item = Suite> {
    suites::ALL_TLS13_CIPHER_SUITES
        .iter()
        .map(|s| Suite::Tls13(s))
        .chain(
            suites::ALL_TLS12_CIPHER_SUITES
                .iter()
                .map(|s| Suite::Tls12(s)),
        )
}

/// Client and server configs that will negotiate exactly `suite`.
fn configs(suite: Suite) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let (tls12, tls13, key_dir) = match suite {
        Suite::Tls12(s) => {
            let key_dir = match format!("{:?}", s.common.suite).contains("_ECDSA_") {
                true => "ecdsa-p256",
                false => "rsa-2048",
            };
            (vec![s], vec![], key_dir)
        }
        Suite::Tls13(s) => (vec![], vec![s], "ecdsa-p256"),
    };

    let provider = Arc::new(CryptoProvider {
        tls12_cipher_suites: Cow::Owned(tls12),
        tls13_cipher_suites: Cow::Owned(tls13),
        ..rustls_graviola::default_provider()
    });

    let chain = CertificateDer::pem_file_iter(format!("tests/keys/{key_dir}/end.fullchain"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(format!("tests/keys/{key_dir}/end.key")).unwrap();
    let server_config = ServerConfig::builder(provider.clone())
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(chain).unwrap()), key)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(format!("tests/keys/{key_dir}/ca.cert")).unwrap())
        .unwrap();
    let client_config = ClientConfig::builder(provider)
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth()
        .unwrap();

    (client_config.into(), server_config.into())
}

/// A connected client and server, with the buffers between them.
struct Pair {
    client: ClientConnection,
    client_input: VecInput,
    client_tls: Vec<u8>,
    server: ServerConnection,
    server_input: VecInput,
    server_tls: Vec<u8>,
}

impl Pair {
    /// Makes a new pair and completes the handshake.
    fn new(client_config: &Arc<ClientConfig>, server_config: &Arc<ServerConfig>) -> Self {
        let mut client_tls = Vec::new();
        let client = client_config
            .connect("localhost".try_into().unwrap())
            .build(&mut client_tls)
            .unwrap();
        let mut pair = Self {
            client,
            client_input: VecInput::default(),
            client_tls,
            server: ServerConnection::new(server_config.clone()).unwrap(),
            server_input: VecInput::default(),
            server_tls: Vec::new(),
        };

        while pair.client.is_handshaking() || pair.server.is_handshaking() {
            pair.client_to_server();
            pair.server_to_client();
        }

        // TLS1.3 servers send tickets after the handshake
        pair.server_to_client();
        pair
    }

    /// Delivers pending client TLS data to the server; returns how many
    /// plaintext bytes the server received.
    fn client_to_server(&mut self) -> usize {
        transfer(
            &mut self.client_tls,
            &mut self.server_input,
            &mut self.server,
            &mut self.server_tls,
        )
    }

    fn server_to_client(&mut self) -> usize {
        transfer(
            &mut self.server_tls,
            &mut self.client_input,
            &mut self.client,
            &mut self.client_tls,
        )
    }
}

fn transfer(
    tls: &mut Vec<u8>,
    input: &mut VecInput,
    conn: &mut impl Connection,
    conn_tls: &mut Vec<u8>,
) -> usize {
    let mut received = 0;
    let mut offs = 0;
    while offs < tls.len() {
        offs += input.read(&mut &tls[offs..]).unwrap();

        let mut iter = conn.read_tls(input, conn_tls);
        while let Some(payload) = iter.next_payload() {
            received += black_box(payload.unwrap().bytes()).len();
        }
    }
    tls.clear();
    received
}

criterion_group!(benches, bulk);
criterion_main!(benches);
