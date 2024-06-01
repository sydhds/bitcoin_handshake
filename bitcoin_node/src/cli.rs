use std::net::IpAddr;
// use std::path::PathBuf;
use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(name = "bitcoin-node")]
#[command(about = "bitcoin node handshake", long_about = None)]
pub struct Cli {
    #[arg(short = 'i', long = "ip", help = "Bitcoin node ip address")]
    pub(crate) ip: IpAddr,
    #[arg(short = 'p', long = "port", help = "Bitcoin node port number")]
    pub(crate) port: u16,
}
