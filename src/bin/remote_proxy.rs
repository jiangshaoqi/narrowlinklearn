use std::{fs, net::SocketAddr, sync::Arc};

use quinn::{crypto::rustls::QuicServerConfig, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    
    // load dummy cert and key
    let cert_file = fs::read("dummycert.der")?;
    let dummy_cert = vec![CertificateDer::from(cert_file)];
    let key_file = fs::read("dummykey.der")?;
    let dummy_key = PrivateKeyDer::try_from(key_file)?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(dummy_cert, dummy_key)?;

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    // hardcode setting, to match the remote proxy in local_proxy
    let server_addr: SocketAddr = "127.0.0.1:1081".parse()?;
    let endpoint = quinn::Endpoint::server(server_config, server_addr)?;

    // in our test, there is only one local connection. Thus no need while loop
    if let Some(conn) = endpoint.accept().await {
        todo!("handle connection, deal with streams, and then parse SOCKS5")
    }

    Ok(())
}

