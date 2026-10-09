//! Simple HTTPS GET client.
//!
//! First parameter is the mandatory URL to GET.
//! Second parameter is an optional path to CA store.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
use std::{env, io};

use http::Uri;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_util::StreamOwned;

fn main() {
    // Send GET request and inspect result, with proper error handling.
    if let Err(e) = run_client() {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::other(err)
}

fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // First parameter is target URL (mandatory).
    let url = match env::args().nth(1) {
        Some(ref url) => Uri::from_str(url).map_err(|e| error(format!("{e}")))?,
        None => {
            println!("Usage: client <url> <ca_store>");
            return Ok(());
        }
    };

    if url.scheme_str() != Some("https") {
        return Err(error(format!("only https URLs are supported: {url}")).into());
    }

    let host = url
        .host()
        .ok_or_else(|| error(format!("URL has no host: {url}")))?
        .to_owned();
    let port = url.port_u16().unwrap_or(443);
    let path = url.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Second parameter is custom Root-CA store (optional, defaults to webpki-roots).
    let roots = match env::args().nth(2) {
        Some(path) => {
            // Read trust roots
            let certs = CertificateDer::pem_file_iter(&path)?.collect::<Result<Vec<_>, _>>()?;
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(certs);
            roots
        }
        None => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        },
    };

    let config = ClientConfig::builder(Arc::new(rustls_graviola::default_provider()))
        .with_root_certificates(roots)
        .with_no_client_auth()?;

    let server_name = ServerName::try_from(host.clone())?;
    let mut output = Vec::new();
    let conn = Arc::new(config).connect(server_name).build(&mut output)?;
    let sock = TcpStream::connect((host.as_str(), port))?;
    let mut tls = StreamOwned::new(conn, sock, output);

    write!(
        tls,
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n"
    )?;

    let mut response = Vec::new();
    tls.read_to_end(&mut response)?;
    println!("{}", String::from_utf8_lossy(&response));

    Ok(())
}
