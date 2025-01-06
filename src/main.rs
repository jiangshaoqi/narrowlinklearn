use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

use localproxy::SOCKClient;



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // local socks proxy
    let listener = TcpListener::bind("127.0.0.1:1080").await?;
    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(handle_socks_stream(client_stream));
    }

    Ok(())
}


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
