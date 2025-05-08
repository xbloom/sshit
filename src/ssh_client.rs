use anyhow::{Result, anyhow};
use log::{info, error};
use ssh2::Session;
use std::net::TcpStream;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::ssh_server::SshServer;

pub struct SshClient {
    host: String,
    port: u16,
    username: String,
    key_path: PathBuf,
    session: Option<Arc<Mutex<Session>>>,
}

impl SshClient {
    pub fn new(host: String, port: u16, username: String, key_path: PathBuf) -> Self {
        Self {
            host,
            port,
            username,
            key_path,
            session: None,
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        // Connect to the remote server
        let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port))?;
        
        // Create a new SSH session
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        
        // Authenticate with the private key
        sess.userauth_pubkey_file(
            &self.username,
            Some(&self.key_path.with_extension("pub")),
            &self.key_path,
            None,
        )?;
        
        if !sess.authenticated() {
            return Err(anyhow!("SSH authentication failed"));
        }
        
        info!("Successfully connected to {}:{}", self.host, self.port);
        self.session = Some(Arc::new(Mutex::new(sess)));
        
        Ok(())
    }

    pub async fn forward_remote_port(&self, remote_port: u16, ssh_server: SshServer, _remote_host: String) -> Result<()> {
        if self.session.is_none() {
            return Err(anyhow!("Not connected to SSH server"));
        }

        let session_arc = self.session.as_ref().unwrap().clone();
        
        // Start a background task to handle remote port forwarding
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", remote_port)).await.unwrap();
            info!("Listening for SSH connections on port {}", remote_port);
            
            loop {
                match listener.accept().await {
                    Ok((remote_stream, remote_addr)) => {
                        info!("Accepted connection from {}", remote_addr);
                        
                        // Clone resources for the new connection
                        let session_clone = session_arc.clone();
                        let ssh_server_clone = ssh_server.clone();
                        
                        // Handle this connection in a separate task
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(remote_stream, ssh_server_clone, session_clone).await {
                                error!("Error handling connection: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                        break;
                    }
                }
            }
        });
        
        info!("Port forwarding established: {}:{} -> local SSH server", self.host, remote_port);
        
        Ok(())
    }
}

async fn handle_connection(
    remote_stream: tokio::net::TcpStream,
    ssh_server: SshServer,
    _session: Arc<Mutex<Session>>,
) -> Result<()> {
    // Connect to the local SSH server
    let local_stream = ssh_server.connect().await?;
    
    // 创建双向拷贝的任务
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote_stream);
    let (mut local_reader, mut local_writer) = tokio::io::split(local_stream);
    
    // Create two tasks for bidirectional copying
    let client_to_server = tokio::spawn(async move {
        let mut buffer = vec![0; 8192];
        loop {
            match remote_reader.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if local_writer.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    let server_to_client = tokio::spawn(async move {
        let mut buffer = vec![0; 8192];
        loop {
            match local_reader.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if remote_writer.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    
    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }
    
    Ok(())
} 