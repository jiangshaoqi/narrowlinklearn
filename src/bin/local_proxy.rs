use std::fs;
use std::{net::ToSocketAddrs, sync::Arc};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use quinn::{Endpoint, RecvStream, SendStream};

use localproxy::SOCKClient;

// use localproxy::local_quic::NoCertificateVerification;




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: local_proxy less than 2 arguments");
        return Ok(());
    }

    // quic setting up, connect to remote proxy
    // let remote_proxy_addr = "127.0.0.1:1081"
    //     .to_socket_addrs()?
    //     .next()
    //     .expect("could not resolve remote proxy address");
    let remote_proxy_addr = args[1]
        .to_socket_addrs()?
        .next()
        .expect("could not resolve remote proxy address");
    let mut endpoint = Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;

    // only for testing, disable the certificate verification
    // let crypto_config = rustls::ClientConfig::builder()
    //     .dangerous()
    //     .with_custom_certificate_verifier(Arc::new(NoCertificateVerification));

    // fix the certificate store only for proxy
    let mut root_store = rustls::RootCertStore::empty();
    let ca_cert_name = "wciscert.der";
    let ca_cert = fs::read(ca_cert_name).expect("cannot read ca cert");
    let ca_cert = CertificateDer::from(ca_cert);
    root_store.add(ca_cert).expect("cannot add ca cert to store");
    // client cert and client key
    let client_cert_name = "wcis_client_cert.der";
    let client_cert = fs::read(client_cert_name).expect("cannot read client cert");
    let client_cert = CertificateDer::from(client_cert);
    let client_key_name = "wcis_client_key.der";
    let client_key = fs::read(client_key_name).expect("cannot read client key");
    let client_key = PrivateKeyDer::try_from(client_key).expect("cannot convert to private key");
    let mut crypto_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![client_cert], client_key)
        .expect("cannot build crypto config");
    crypto_config.alpn_protocols.push(b"comeonman".to_vec());
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?,
    ));
    endpoint.set_default_client_config(client_config);
    print!("Connecting to remote proxy...");
    // server_name is whatcanisay in this case
    let conn = endpoint.connect(remote_proxy_addr, "whatcanisay")?.await?;
    let conn = Arc::new(conn);
    let conn_clone = Arc::clone(&conn);

    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("cannot get ctrl + c");
        println!("Stopping local proxy");
    };

    tokio::select! {
        _ = async {
            let listener = TcpListener::bind("127.0.0.1:1080").await?;
            loop {
                let (client_stream, _) = listener.accept().await?;
                let remote_proxy_channel = conn.open_bi().await?;
                tokio::spawn(handle_socks_stream(client_stream, remote_proxy_channel));
            }
            #[allow(unreachable_code)]
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        } => {},
        _ = ctrl_c => { 
            conn_clone.close(0u32.into(), b"gracefully shutdown");
            println!("client stop successfully");
        }
    }

    // local socks proxy, wait for browser to connect
    // let listener = TcpListener::bind("127.0.0.1:1080").await?;
    // loop {
    //     let (client_stream, _) = listener.accept().await?;
    //     let remote_proxy_channel = conn.open_bi().await?;
    //     tokio::spawn(handle_socks_stream(client_stream, remote_proxy_channel));
    // }

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
