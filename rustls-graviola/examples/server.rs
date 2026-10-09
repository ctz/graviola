//! Simple HTTPS server, which echoes back the request it received.
//!
//! Parameters are the port to use, and the certificate chain and private key
//! files.

use std::io::{BufRead, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::{env, io, thread};

use rustls::crypto::Identity;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{Connection, ServerConfig, ServerConnection};
use rustls_util::StreamOwned;

fn main() {
    // Serve an echo service over HTTPS, with proper error handling.
    if let Err(e) = run_server() {
        eprintln!("FAILED: {e}");
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::other(err)
}

fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = env::args();
    args.next();
    let (port, cert_file, key_file) = match (args.next(), args.next(), args.next()) {
        (Some(port), Some(cert_file), Some(key_file)) => (port.parse()?, cert_file, key_file),
        _ => {
            println!("usage: <PORT> <CERT> <KEY>");
            std::process::exit(1);
        }
    };
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    // Load public certificate.
    let certs = CertificateDer::pem_file_iter(&cert_file)?.collect::<Result<Vec<_>, _>>()?;
    // Load private key.
    let key = PrivateKeyDer::from_pem_file(&key_file)?;

    // Build TLS configuration.
    let server_config = ServerConfig::builder(Arc::new(rustls_graviola::default_provider()))
        .with_no_client_auth()
        .with_single_cert(Arc::new(Identity::from_cert_chain(certs)?), key)
        .map_err(|e| error(e.to_string()))?;
    let server_config = Arc::new(server_config);

    println!("Starting to serve on https://{addr}");
    let incoming = TcpListener::bind(addr)?;

    for tcp_stream in incoming.incoming() {
        let tcp_stream = tcp_stream?;
        let server_config = server_config.clone();
        thread::spawn(move || {
            if let Err(err) = serve_connection(server_config, tcp_stream) {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }

    Ok(())
}

/// Read a HTTP request head, and send it back as the response body.
fn serve_connection(server_config: Arc<ServerConfig>, tcp_stream: TcpStream) -> io::Result<()> {
    let conn = ServerConnection::new(server_config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, tcp_stream, Vec::new());

    let mut request = Vec::new();
    loop {
        let len = tls.read_until(b'\n', &mut request)?;
        if len == 0 || request.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    write!(
        tls,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        request.len()
    )?;
    tls.write_all(&request)?;
    tls.conn
        .send_close_notify(&mut tls.output)
        .map_err(io::Error::other)?;
    tls.flush()
}
