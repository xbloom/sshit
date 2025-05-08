use anyhow::Result;
use log::info;
use tokio::net::TcpStream;

/// SSH server that proxies connections to a local SSH server
#[derive(Clone)]
pub struct SshServer {
    pub local_host: String,
    pub local_port: u16,
}

impl SshServer {
    pub fn new(local_host: String, local_port: u16) -> Self {
        Self {
            local_host,
            local_port,
        }
    }
    
    /// Connect to the local SSH server
    pub async fn connect(&self) -> Result<TcpStream> {
        let conn_str = format!("{}:{}", self.local_host, self.local_port);
        info!("连接到本地 SSH 服务器 {}", conn_str);
        
        let stream = TcpStream::connect(conn_str).await?;
        Ok(stream)
    }
} 