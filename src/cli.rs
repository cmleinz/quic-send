use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Clone, Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub commands: Commands,

    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    pub key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,

    /// file to log TLS keys to for debugging
    #[clap(long = "keylog", default_value_t = false)]
    pub keylog: bool,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Commands {
    Sender {
        file: PathBuf,
        #[clap(short, long = "destination")]
        destination: std::net::SocketAddr,
    },

    Receiver {
        file: PathBuf,
        #[clap(short, long = "listen", default_value = "[::1]:4433")]
        listen: std::net::SocketAddr,
    },
}
