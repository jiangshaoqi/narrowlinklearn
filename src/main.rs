use std::{net::ToSocketAddrs, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use quinn::Endpoint;

use localproxy::SOCKClient;

mod local_quic;
use local_quic::NoCertificateVerification;




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // connect to remote proxy
    let remote_proxy_addr = "127.0.0.1:1081"
        .to_socket_addrs()?
        .next()
        .expect("could not resolve remote proxy address");
    let mut endpoint = Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
    let crypto_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    endpoint.set_default_client_config(client_config);
    let conn = endpoint.connect(remote_proxy_addr, "localhost")?.await?;


    // local socks proxy
    let listener = TcpListener::bind("127.0.0.1:1080").await?;
    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(handle_socks_stream(client_stream));
    }

    Ok(())
}


// todo: set the conn as the input and forward the data to the remote proxy
async fn handle_socks_stream(client_stream: TcpStream) {
    let mut client = SOCKClient::new(client_stream, None).await;

    match client.init().await {
        Ok(_) => {
            println!("Client connected");
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}
