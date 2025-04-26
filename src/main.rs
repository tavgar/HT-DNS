mod proto;
mod fec;
mod crypto;
mod server;
mod client;
mod util;

use server::{HTDNSServer, Server, ServerConfig};
use client::{HTDNSClient, Client, ClientConfig};

fn main() {
    println!("HT-DNS skeleton – compile-time test.");

    // quick smoke-test build (disabled at runtime)
    #[cfg(test)]
    {
        let _s = HTDNSServer::new(ServerConfig::default()).unwrap();
        let _c = HTDNSClient::new(ClientConfig::default()).unwrap();
    }
}
