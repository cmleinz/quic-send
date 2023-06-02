use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use quinn::{ClientConfig, Endpoint, ServerConfig};
mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.commands {
        Commands::Sender { file, destination } => run_client(destination, file).await,
        Commands::Receiver { file, listen } => run_server(listen, file).await,
    }
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}

pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, Vec<u8>)> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

/// Runs a QUIC server bound to given address.
async fn run_server(addr: SocketAddr, save_path: PathBuf) -> Result<()> {
    let (endpoint, _server_cert) = make_server_endpoint(addr)?;
    // accept a single connection
    if let Some(conn) = endpoint.accept().await {
        let (_, mut receiver) = conn.await?.accept_bi().await?;
        let mut file = tokio::fs::File::create(save_path).await?;

        tokio::io::copy(&mut receiver, &mut file).await?;
    }
    Ok(())
}

async fn run_client(server_addr: SocketAddr, file_path: PathBuf) -> Result<()> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(configure_client());

    println!("Attempting to connect to server {:?}", server_addr);
    // connect to server
    let (mut sender, _recv) = endpoint
        .connect(server_addr, "localhost")?
        .await?
        .open_bi()
        .await?;

    println!("Connected to server");

    let mut file = tokio::fs::File::open(file_path).await?;

    tokio::io::copy(&mut file, &mut sender).await?;
    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}
