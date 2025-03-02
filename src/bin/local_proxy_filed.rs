use std::{env::args, net::ToSocketAddrs, sync::Arc};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{io::AsyncWriteExt, net::{TcpListener, TcpStream}};
use quinn::{Endpoint, RecvStream, SendStream};

use localproxy::SOCKClient;

// use localproxy::local_quic::NoCertificateVerification;
static CLIENT_CERT: &[u8] = include_bytes!("../../wcis_client_cert.der");
static CLIENT_KEY: &[u8] = include_bytes!("../../wcis_client_key.der");

static CA_CERT: &[u8] = include_bytes!("../../wciscert.der");



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    let args = args().collect::<Vec<String>>();
    
    let remote_proxy_addr;
    if args.len() > 1 {
        remote_proxy_addr = match args[1].to_socket_addrs() {
            Ok(mut addr_iter) => {
                addr_iter.next().expect("cannot resolve address")
            },
            Err(e) => {
                eprintln!("Invalid input address: {}\nSet into default remote address", e);
                "20.83.146.179:443"
                    .to_socket_addrs()?
                    .next()
                    .expect("could not resolve remote proxy address")
            },
        };
    } else {
        remote_proxy_addr = "20.83.146.179:443"
            .to_socket_addrs()?
            .next()
            .expect("could not resolve remote proxy address");
    }

    // local testing
    // let remote_proxy_addr = "127.0.0.1:443"
    //     .to_socket_addrs()?
    //     .next()
    //     .expect("could not resolve remote proxy address");
    
    // let remote_proxy_addr = "20.83.146.179:443"
    //     .to_socket_addrs()?
    //     .next()
    //     .expect("could not resolve remote proxy address");
    let mut endpoint = Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;

    // fix the certificate store only for proxy
    let mut root_store = rustls::RootCertStore::empty();
    let ca_cert = CertificateDer::from(CA_CERT);
    root_store.add(ca_cert).expect("cannot add ca cert to store");
    // client cert and client key
    let client_cert = CertificateDer::from(CLIENT_CERT);
    let client_key = PrivateKeyDer::try_from(CLIENT_KEY).expect("cannot convert to private key");
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
    let conn = endpoint.connect(remote_proxy_addr, "whatcanisay")
        .expect("cannot connect to endpoint").await
        .expect("cannot connect to remote proxy");
    print!("Connected to remote proxy\n");
    let conn = Arc::new(conn);
    let conn_clone = Arc::clone(&conn);

    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("cannot get ctrl + c");
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
            endpoint.close(0u32.into(), b"gracefully shutdown");
            endpoint.wait_idle().await;
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
                
                (_, _) => {
                    let _ = remote_proxy_write.shutdown().await;
                    let _ = socks_write.shutdown().await;
                    println!("Stream closed");
                },
            }
            
        }
        Err(e) => {
            println!("Error in local_init: {:?}", e);
        }
    }
    
}
