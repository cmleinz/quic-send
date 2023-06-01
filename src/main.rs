use std::{
    env::args,
    sync::Arc,
    time::{Duration, Instant},
};

use humansize::{file_size_opts, FileSize};

use futures_util::StreamExt;
use rustls::PrivateKey;
use tokio::{
    fs::File,
    io::{self, AsyncWriteExt},
    time::sleep,
};

const CERT: &[u8] = include_bytes!("../cert.der");
const PRIV: &[u8] = include_bytes!("../cert.priv");

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    let args = args().collect::<Vec<_>>();

    // according to the source code,
    // datagram_receive_buffer_size = stream_receive_window = max_bandwidth * rtt
    // send_window = stream_receive_window * 8
    // const MAX_BW: u64 = 1_000_000_000 / 8; // 1gbps
    // const RTT_MS: u64 = 300;
    // let transport_config = TransportConfig::default();
    // transport_config
    //     .stream_receive_window(MAX_BW / 1000 * RTT_MS)
    //     .unwrap()
    //     .datagram_receive_buffer_size(Some((MAX_BW / 1000 * RTT_MS).try_into().unwrap()))
    //     .send_window(MAX_BW / 1000 * RTT_MS * 8);

    match args[1].as_str() {
        // this is just done once to generate certs, which are then included into the binary with the above include's
        "certgen" => {
            let cert =
                rcgen::generate_simple_self_signed(vec!["quic-file-transfer".into()]).unwrap();
            let cert_der = cert.serialize_der().unwrap();
            let priv_key = cert.serialize_private_key_der();

            let mut f = File::create("cert.der").await.unwrap();
            f.write_all(&cert_der).await.unwrap();

            let mut f = File::create("cert.priv").await.unwrap();
            f.write_all(&priv_key).await.unwrap();
        }
        "server" => {
            let sockaddr = "0.0.0.0:8080".parse().unwrap();

            // let mut server_config = ServerConfig::default();
            // server_config.transport = Arc::new(transport_config);
            let crypto_cfg = rustls::ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::Certificate(CERT.into())],
                    PrivateKey(PRIV.into()),
                )
                .unwrap();

            let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto_cfg));

            let (_endpoint, mut incoming) = quinn::Endpoint::server(server_cfg, sockaddr).unwrap();

            let mut nc = incoming.next().await.unwrap().await.unwrap();

            let connection = nc.connection;
            tokio::spawn(async move {
                // let mut last_stream = 0;
                // let max_d = connection.max_datagram_size().unwrap() as u64;
                loop {
                    let stats = connection.stats();
                    eprintln!("{:?}", stats);
                    // This doesn't actually get proper rate. I don't think it's exposed.
                    // eprintln!(
                    //     "{} MB/s",
                    //     (max_d * (stats.frame_rx.stream - last_stream)) as f64 / 1e6
                    // );
                    // last_stream = stats.frame_rx.stream;
                    sleep(Duration::from_secs(1)).await;
                }
            });

            eprintln!("Got connection");

            let (_s, mut r) = nc.bi_streams.next().await.unwrap().unwrap();

            eprintln!("Got stream");

            let mut stdout = tokio::io::stdout();

            let begin = Instant::now();
            let bytes = io::copy(&mut r, &mut stdout).await.unwrap();
            let end = Instant::now();

            eprintln!(
                "Received {} in {:?}, {:.4} MB/s",
                bytes.file_size(file_size_opts::CONVENTIONAL).unwrap(),
                end - begin,
                bytes as f64 / (end - begin).as_secs_f64() / 1e6
            )
        }
        "client" => {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(&rustls::Certificate(CERT.into())).unwrap();

            let client_crypto = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            // cfg_builder
            //     .add_certificate_authority(Certificate::from_der(CERT).unwrap())
            //     .unwrap()
            //     .enable_0rtt();

            // client_cfg.transport = Arc::new(transport_config);
            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

            let conn = endpoint
                .connect(
                    format!("{}:1234", args[2]).parse().unwrap(),
                    "quic-file-transfer",
                )
                .unwrap()
                .await
                .unwrap();

            eprintln!("Got connection");

            let (mut s, _r) = conn.connection.open_bi().await.unwrap();

            let c_arc = Arc::new(conn.connection);
            let c_arc2 = c_arc.clone();
            tokio::spawn(async move {
                loop {
                    eprintln!("{:?}", c_arc2.stats());
                    sleep(Duration::from_secs(1)).await;
                }
            });

            eprintln!("Got stream");

            let mut stdin = tokio::io::stdin();

            let begin = Instant::now();
            let bytes = io::copy(&mut stdin, &mut s).await.unwrap();
            let end = Instant::now();

            s.finish().await.unwrap();
            c_arc.close(0u32.into(), b"done");
            eprintln!(
                "Sent {} in {:?}, {:.4} MB/s",
                bytes.file_size(file_size_opts::CONVENTIONAL).unwrap(),
                end - begin,
                bytes as f64 / (end - begin).as_secs_f64() / 1e6
            )
        }
        e => panic!("Bad config {}", e),
    }
}
