use std::{fs, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};

use localproxy::{local_quic::OneCertVerification, ResponseCode, SOCKSReq, SocksReply};
use quinn::{crypto::rustls::QuicServerConfig, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {

    rustls::crypto::aws_lc_rs::default_provider().install_default().expect("install aws lc provider failed");

    // args[1] is the remote proxy address
    let args: Vec<String> = std::env::args().collect();
    
    // load dummy cert and key
    // if path::Path::new("dummycert.der").exists() == false || path::Path::new("dummykey.der").exists() == false {
    //     let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    //     let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    //     let cert: CertificateDer = cert.cert.into();
    //     fs::write("dummycert.der", &cert)?;
    //     fs::write("dummykey.der", key.secret_pkcs8_der())?;
    // }
    // let cert_file = fs::read("dummycert.der")?;
    // let dummy_cert = vec![CertificateDer::from(cert_file)];
    // let key_file = fs::read("dummykey.der")?;
    // let dummy_key = PrivateKeyDer::try_from(key_file)?;

    // let server_crypto = rustls::ServerConfig::builder()
    //     .with_no_client_auth()
    //     .with_single_cert(dummy_cert, dummy_key)?;

    let cert_file = fs::read("wcis_server_cert.der")?;
    let server_cert = vec![CertificateDer::from(cert_file)];
    let key_file = fs::read("wcis_server_key.der")?;
    let server_key = PrivateKeyDer::try_from(key_file)?;

    let ca_cert_path = "wciscert.der";

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(OneCertVerification::new(ca_cert_path)))
        .with_single_cert(server_cert, server_key)?;
    server_crypto.alpn_protocols.push(b"comeonman".to_vec());
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into())
        .keep_alive_interval(Some(Duration::from_secs(5)));

    // hardcode setting, to match the remote proxy in local_proxy
    // let server_addr: SocketAddr = "127.0.0.1:1081".parse()?;
    // read first argument as server address
    let server_addr: SocketAddr = args[1].parse()?;
    let endpoint = quinn::Endpoint::server(server_config, server_addr)?;

    // in our test, there is only one client connection. Thus no need while loop
    while let Some(conn) = endpoint.accept().await {
        tokio::spawn(async move {
            match conn.await {
                Ok(connection) => {
                    println!("Connection established");
                    while let Ok(stream) = connection.accept_bi().await {
                            tokio::spawn(handle_socks_stream(stream));
                    };
                },
                Err(e) => {
                    println!("Connection error: {:?}", e);
                }
            }
        });
    }

    Ok(())
}


async fn handle_socks_stream(
    stream: (SendStream, RecvStream)
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let (mut server_write, mut server_read) = stream;
    
    let socks_req = SOCKSReq::from_quinn_recv_stream(&mut server_read).await?;
    match socks_req.command {
        localproxy::SockCommand::Connect => {
            println!("Connecting to {:?}", socks_req.addr);

            let sock_addr = localproxy::addr_to_socket(&socks_req.addr_type, &socks_req.addr, socks_req.port).await?;
            let time_out = Duration::from_millis(500);

            let mut target =
                timeout(
                    time_out,
                    async move { TcpStream::connect(&sock_addr[..]).await },
                )
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "timeout"))??;
            let (mut target_read, mut target_write) = target.split();
            

            SocksReply::new(ResponseCode::Success)
                .send_quinn(&mut server_write)
                .await?;

            let up_channal = tokio::io::copy(&mut server_read, &mut target_write);
            let down_channal = tokio::io::copy(&mut target_read, &mut server_write);
            match tokio::join!(up_channal, down_channal) {
                (Ok(_), Ok(_)) => (),
                (Err(e), _) | (_, Err(e)) => {
                    println!("Error in data transfer: {:?}", e);
                }
            }

            // match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
            //     // ignore not connected for shutdown error
            //     Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
            //         return Ok(0);
            //     },
            //     Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
            //     Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
            // }
        },
        localproxy::SockCommand::Bind => {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bind not supported")));
        },
        localproxy::SockCommand::UdpAssosiate => {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UDP not supported")));
        },
    }

    Ok(())
}

