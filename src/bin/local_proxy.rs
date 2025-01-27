use std::{net::ToSocketAddrs, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use quinn::{Endpoint, RecvStream, SendStream};

use localproxy::SOCKClient;

use localproxy::local_quic::NoCertificateVerification;




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    // quic setting up, connect to remote proxy
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
    print!("Connecting to remote proxy...");
    let conn = endpoint.connect(remote_proxy_addr, "localhost")?.await?;


    // local socks proxy, wait for browser to connect
    let listener = TcpListener::bind("127.0.0.1:1080").await?;
    loop {
        let (client_stream, _) = listener.accept().await?;
        let remote_proxy_channel = conn.open_bi().await?;
        tokio::spawn(handle_socks_stream(client_stream, remote_proxy_channel));
    }

    Ok(())
}


// todo: set the conn as the input and forward the data to the remote proxy
async fn handle_socks_stream(
    client_stream: TcpStream,
    remote_proxy_channel: (SendStream, RecvStream),
) {
    let (mut remote_proxy_write, mut remote_proxy_read) = remote_proxy_channel;

    let mut client = SOCKClient::new(client_stream, None).await;

    // match client.init().await {
    //     Ok(_) => {
    //         println!("Client connected");
    //     }
    //     Err(e) => {
    //         println!("Error: {:?}", e);
    //     }
    // }

    match client.local_init().await {
        Ok(_) => {
            let (mut socks_read, mut socks_write) = client.stream.into_split();
            let up_channal = tokio::io::copy(&mut socks_read, &mut remote_proxy_write);
            let down_channal = tokio::io::copy(&mut remote_proxy_read, &mut socks_write);
            match tokio::join!(up_channal, down_channal) {
                (Ok(_), Ok(_)) => (),
                (Err(e), _) | (_, Err(e)) => {
                    println!("Error in data transfer: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("Error in local_init: {:?}", e);
        }
    }
    
}
