//! Server implementation for the `bore` service.

use std::net::{IpAddr, Ipv4Addr};
use std::{io, ops::RangeInclusive, sync::Arc, time::Duration};

use anyhow::Result;
use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tracing::{info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{proxy, ClientMessage, Delimited, ServerMessage, CONTROL_PORT};

/// State structure for the server.
pub struct Server {
    /// Range of TCP ports that can be forwarded.
    port_range: RangeInclusive<u16>,

    /// Optional secret used to authenticate clients.
    auth: Option<Authenticator>,

    /// Concurrent map of IDs to incoming connections.
    conns: Arc<DashMap<Uuid, TcpStream>>,

    /// IP address where the control server will bind to.
    bind_addr: IpAddr,

    /// IP address where tunnels will listen on.
    bind_tunnels: IpAddr,

    /// Whether subdomain routing is enabled.
    subdomain_routing: bool,

    /// Base domain for subdomain routing.
    domain: String,

    /// Map of active subdomains to client port information.
    subdomains: Arc<DashMap<String, u16>>,
}

impl Server {
    /// Create a new server with a specified minimum port number.
    pub fn new(port_range: RangeInclusive<u16>, secret: Option<&str>) -> Self {
        assert!(!port_range.is_empty(), "must provide at least one port");
        Server {
            port_range,
            conns: Arc::new(DashMap::new()),
            auth: secret.map(Authenticator::new),
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            subdomain_routing: false,
            domain: String::new(),
            subdomains: Arc::new(DashMap::new()),
        }
    }

    /// Set the IP address where tunnels will listen on.
    pub fn set_bind_addr(&mut self, bind_addr: IpAddr) {
        self.bind_addr = bind_addr;
    }

    /// Set the IP address where the control server will bind to.
    pub fn set_bind_tunnels(&mut self, bind_tunnels: IpAddr) {
        self.bind_tunnels = bind_tunnels;
    }
    /// Start an HTTP proxy server for subdomain routing
    async fn start_http_proxy(&self, port: u16) -> Result<()> {
        let listener = TcpListener::bind((self.bind_addr, port)).await?;
        let subdomains = Arc::clone(&self.subdomains);
        let domain = self.domain.clone();
        let bind_addr = self.bind_addr;

        info!(port, "HTTP proxy server listening for subdomains");

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, addr)) => {
                        let subdomains = Arc::clone(&subdomains);
                        let domain = domain.clone();

                        tokio::spawn(async move {
                            info!(?addr, "new HTTP connection");

                            // Read the HTTP request to extract the Host header
                            let mut buffer = [0; 4096];
                            match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
                                Ok(n) if n > 0 => {
                                    let request = String::from_utf8_lossy(&buffer[..n]);

                                    // Extract the Host header
                                    if let Some(host_line) = request
                                        .lines()
                                        .find(|line| line.to_lowercase().starts_with("host:"))
                                    {
                                        let host = host_line[5..].trim();
                                        info!(?host, "HTTP request for host");

                                        // Check if this is a subdomain request
                                        if host.ends_with(&domain) {
                                            let subdomain = if let Some(idx) = host.find('.') {
                                                &host[0..idx]
                                            } else {
                                                ""
                                            };

                                            if let Some(client_port) = subdomains.get(subdomain) {
                                                info!(?subdomain, "found matching subdomain");

                                                // Forward the request to the tunnel port
                                                if let Ok(mut tunnel_stream) =
                                                    TcpStream::connect((bind_addr, *client_port))
                                                        .await
                                                {
                                                    // Forward the initial request
                                                    if let Err(e) =
                                                        tunnel_stream.write_all(&buffer[..n]).await
                                                    {
                                                        warn!("error forwarding request: {}", e);
                                                        return;
                                                    }

                                                    // Now proxy the rest of the connection
                                                    if let Err(e) =
                                                        proxy(stream, tunnel_stream).await
                                                    {
                                                        warn!("error proxying connection: {}", e);
                                                    }
                                                    return;
                                                } else {
                                                    warn!("could not connect to tunnel port");
                                                }
                                            } else {
                                                warn!(?subdomain, "subdomain not found");
                                            }
                                        }
                                    }

                                    // If we get here, there was no valid subdomain or we couldn't connect
                                    let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nSubdomain not found";
                                    let _ = stream.write_all(response.as_bytes()).await;
                                }
                                _ => {}
                            }
                        });
                    }
                    Err(e) => {
                        warn!("error accepting HTTP connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
    /// Enable subdomain routing with the given base domain.
    pub fn enable_subdomain_routing(&mut self, domain: &str) {
        self.subdomain_routing = true;
        self.domain = domain.to_string();
    }

    /// Generate a unique subdomain for a client.
    fn generate_subdomain(&self) -> String {
        // Generate a random subdomain with a UUID to ensure uniqueness
        format!("user-{}", Uuid::new_v4().simple())
    }

    /// Start the server, listening for new connections.
    pub async fn listen(self) -> Result<()> {
        let this = Arc::new(self);

        // Start HTTP proxy server if subdomain routing is enabled
        if this.subdomain_routing {
            // Start HTTP proxy on port 1337
            if let Err(e) = this.start_http_proxy(1337).await {
                warn!("Failed to start HTTP proxy on port 1337: {}. Will continue without HTTP routing.", e);
            }
        }

        let listener = TcpListener::bind((this.bind_addr, CONTROL_PORT)).await?;
        info!(addr = ?this.bind_addr, "server listening");

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = Arc::clone(&this);
            tokio::spawn(
                async move {
                    info!("incoming connection");
                    if let Err(err) = this.handle_connection(stream).await {
                        warn!(%err, "connection exited with error");
                    } else {
                        info!("connection exited");
                    }
                }
                .instrument(info_span!("control", ?addr)),
            );
        }
    }

    async fn create_listener(&self, port: u16) -> Result<TcpListener, &'static str> {
        let try_bind = |port: u16| async move {
            TcpListener::bind((self.bind_tunnels, port))
                .await
                .map_err(|err| match err.kind() {
                    io::ErrorKind::AddrInUse => "port already in use",
                    io::ErrorKind::PermissionDenied => "permission denied",
                    _ => "failed to bind to port",
                })
        };
        if port > 0 {
            // Client requests a specific port number.
            if !self.port_range.contains(&port) {
                return Err("client port number not in allowed range");
            }
            try_bind(port).await
        } else {
            // Client requests any available port in range.
            //
            // In this case, we bind to 150 random port numbers. We choose this value because in
            // order to find a free port with probability at least 1-δ, when ε proportion of the
            // ports are currently available, it suffices to check approximately -2 ln(δ) / ε
            // independently and uniformly chosen ports (up to a second-order term in ε).
            //
            // Checking 150 times gives us 99.999% success at utilizing 85% of ports under these
            // conditions, when ε=0.15 and δ=0.00001.
            for _ in 0..150 {
                let port = fastrand::u16(self.port_range.clone());
                match try_bind(port).await {
                    Ok(listener) => return Ok(listener),
                    Err(_) => continue,
                }
            }
            Err("failed to find an available port")
        }
    }

    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        let mut stream = Delimited::new(stream);
        if let Some(auth) = &self.auth {
            if let Err(err) = auth.server_handshake(&mut stream).await {
                warn!(%err, "server handshake failed");
                stream.send(ServerMessage::Error(err.to_string())).await?;
                return Ok(());
            }
        }

        match stream.recv_timeout().await? {
            Some(ClientMessage::Authenticate(_)) => {
                warn!("unexpected authenticate");
                Ok(())
            }
            Some(ClientMessage::Hello(port)) => {
                let listener = match self.create_listener(port).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        stream.send(ServerMessage::Error(err.into())).await?;
                        return Ok(());
                    }
                };
                let host = listener.local_addr()?.ip();
                let port = listener.local_addr()?.port();

                if self.subdomain_routing {
                    let subdomain = self.generate_subdomain();
                    info!(?host, ?port, subdomain, "new client with subdomain");
                    // Register the subdomain with the assigned port
                    self.subdomains.insert(subdomain.clone(), port);

                    // Send the port and subdomain information to the client
                    stream
                        .send(ServerMessage::HelloWithSubdomain {
                            port,
                            subdomain,
                            domain: self.domain.clone(),
                        })
                        .await?;
                } else {
                    info!(?host, ?port, "new client");
                    stream.send(ServerMessage::Hello(port)).await?;
                }

                loop {
                    if stream.send(ServerMessage::Heartbeat).await.is_err() {
                        // Assume that the TCP connection has been dropped.
                        return Ok(());
                    }
                    const TIMEOUT: Duration = Duration::from_millis(500);
                    if let Ok(result) = timeout(TIMEOUT, listener.accept()).await {
                        let (stream2, addr) = result?;
                        info!(?addr, ?port, "new connection");

                        let id = Uuid::new_v4();
                        let conns = Arc::clone(&self.conns);

                        conns.insert(id, stream2);
                        tokio::spawn(async move {
                            // Remove stale entries to avoid memory leaks.
                            sleep(Duration::from_secs(10)).await;
                            if conns.remove(&id).is_some() {
                                warn!(%id, "removed stale connection");
                            }
                        });
                        stream.send(ServerMessage::Connection(id)).await?;
                    }
                }
            }
            Some(ClientMessage::Accept(id)) => {
                info!(%id, "forwarding connection");
                match self.conns.remove(&id) {
                    Some((_, mut stream2)) => {
                        let parts = stream.into_parts();
                        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                        stream2.write_all(&parts.read_buf).await?;
                        proxy(parts.io, stream2).await?
                    }
                    None => warn!(%id, "missing connection"),
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
