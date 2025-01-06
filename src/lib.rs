use core::error;
use std::f32::consts::E;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::windows::io::InvalidHandleError;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;



// SOCKS5 protocol version
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;



pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    auth_nmethods: u8,
    socks_version: u8,
    timeout: Option<Duration>,
}

impl<T> SOCKClient<T>
where T: AsyncRead + AsyncWrite + Send + Unpin + 'static
{
    pub async fn new(
        stream: T,
        timeout: Option<Duration>,
    ) -> SOCKClient<T> {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            timeout,
        }
    }


    pub async fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stream.shutdown().await?;
        Ok(())
    }


    pub async fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        print!("Client connected\n");
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).await?;
        print!("Header: {:?}\n", header);

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        match self.socks_version {
            SOCKS_VERSION => {
                self.auth().await?;
                self.handle_client().await?;
            }
            _ => {
                self.shutdown().await?;
            }
        }

        Ok(())
    }


    async fn auth(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // no auth at this time
        let methods = self.get_avalible_methods().await?;
        print!("Methods: {:?}\n", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;
        response[1] = 0x00;

        self.stream.write_all(&response).await?;

        Ok(())
    }


    async fn handle_client(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        let req = SOCKSReq::from_stream(&mut self.stream).await?;

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                print!("Connecting to {:?}", req.addr);
                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port).await?;

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(500)
                };

                let mut target =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "timeout"))??;

                SocksReply::new(ResponseCode::Success)
                    .send(&mut self.stream)
                    .await?;

                match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                        return Ok(0);
                    },
                    Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }

            }
            SockCommand::Bind => {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Bind not supported")));
            }
            SockCommand::UdpAssosiate => {
                return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "UDP not supported")));
            }
        }
    }


    async fn get_avalible_methods(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method).await?;
            
            methods.append(&mut method.to_vec());
            
        }
        Ok(methods)
    }

}



struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16,
}


enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3,
}

impl SockCommand {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None,
        }
    }
}

/// DST.addr variant types
#[derive(PartialEq)]
enum AddrType {
    /// IP V4 address: X'01'
    V4 = 0x01,
    /// DOMAINNAME: X'03'
    Domain = 0x03,
    /// IP V6 address: X'04'
    V6 = 0x04,
}

impl AddrType {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }
}


impl SOCKSReq {
    async fn from_stream<T>(stream: &mut T) -> Result<Self, std::io::Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // From rfc 1928 (S4), the SOCKS request is formed as follows:
        //
        //    +----+-----+-------+------+----------+----------+
        //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //    +----+-----+-------+------+----------+----------+
        //    | 1  |  1  | X'00' |  1   | Variable |    2     |
        //    +----+-----+-------+------+----------+----------+
        //
        // Where:
        //
        //      o  VER    protocol version: X'05'
        //      o  CMD
        //         o  CONNECT X'01'
        //         o  BIND X'02'
        //         o  UDP ASSOCIATE X'03'
        //      o  RSV    RESERVED
        //      o  ATYP   address type of following address
        //         o  IP V4 address: X'01'
        //         o  DOMAINNAME: X'03'
        //         o  IP V6 address: X'04'
        //      o  DST.ADDR       desired destination address
        //      o  DST.PORT desired destination port in network octet
        //         order

        let mut packet = [0u8; 4];
        stream.read_exact(&mut packet).await?;

        if packet[0] != SOCKS_VERSION {
            stream.shutdown().await?;
        }

        // Get command
        let command = match SockCommand::from(packet[1] as usize) {
            Some(com) => Ok(com),
            None => {
                stream.shutdown().await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid command",
                ))
            }
        }?;

        let addr_type = match AddrType::from(packet[3] as usize) {
            Some(addr) => Ok(addr),
            None => {
                stream.shutdown().await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid address type",
                ))
            }
        }?;

        // Get Addr from addr_type and stream
        let addr: Vec<u8> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                domain
            }
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
        };

        // read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;

        // Merge two u8s into u16
        let port = (u16::from(port[0]) << 8) | u16::from(port[1]);

        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            addr_type,
            addr,
            port,
        })
    }
}



/// Convert an address and AddrType to a SocketAddr
async fn addr_to_socket(addr_type: &AddrType, addr: &[u8], port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
    match addr_type {
        AddrType::V6 => {
            let new_addr = (0..8)
                .map(|x| {
                    (u16::from(addr[(x * 2)]) << 8) | u16::from(addr[(x * 2) + 1])
                })
                .collect::<Vec<u16>>();

            Ok(vec![SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::new(
                    new_addr[0],
                    new_addr[1],
                    new_addr[2],
                    new_addr[3],
                    new_addr[4],
                    new_addr[5],
                    new_addr[6],
                    new_addr[7],
                ),
                port,
                0,
                0,
            ))])
        }
        AddrType::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            port,
        ))]),
        AddrType::Domain => {
            let mut domain = String::from_utf8_lossy(addr).to_string();
            domain.push(':');
            domain.push_str(&port.to_string());

            Ok(lookup_host(domain).await?.collect())
        }
    }
}


pub struct SocksReply {
    // From rfc 1928 (S6),
    // the server evaluates the request, and returns a reply formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    // Where:
    //
    //      o  VER    protocol version: X'05'
    //      o  REP    Reply field:
    //         o  X'00' succeeded
    //         o  X'01' general SOCKS server failure
    //         o  X'02' connection not allowed by ruleset
    //         o  X'03' Network unreachable
    //         o  X'04' Host unreachable
    //         o  X'05' Connection refused
    //         o  X'06' TTL expired
    //         o  X'07' Command not supported
    //         o  X'08' Address type not supported
    //         o  X'09' to X'FF' unassigned
    //      o  RSV    RESERVED
    //      o  ATYP   address type of following address
    //         o  IP V4 address: X'01'
    //         o  DOMAINNAME: X'03'
    //         o  IP V6 address: X'04'
    //      o  BND.ADDR       server bound address
    //      o  BND.PORT       server bound port in network octet order
    //
    buf: [u8; 10],
}


impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            // VER
            SOCKS_VERSION,
            // REP
            status as u8,
            // RSV
            RESERVED,
            // ATYP
            1,
            // BND.ADDR
            0,
            0,
            0,
            0,
            // BND.PORT
            0,
            0,
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> std::io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }
}


#[derive(Debug)]
/// Possible SOCKS5 Response Codes
pub enum ResponseCode {
    Success = 0x00,
    Failure = 0x01,
    RuleFailure = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

