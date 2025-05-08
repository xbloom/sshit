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
        info!("正在连接远程服务器 {}:{} 用户名: '{}'", self.host, self.port, self.username);
        let tcp = match TcpStream::connect(format!("{}:{}", self.host, self.port)) {
            Ok(stream) => stream,
            Err(e) => {
                error!("连接远程服务器 {}:{} 失败: {}", self.host, self.port, e);
                return Err(anyhow!("TCP 连接失败: {}", e));
            }
        };
        
        // Create a new SSH session
        let mut sess = Session::new()?;
        sess.set_tcp_stream(tcp);
        
        info!("开始 SSH 握手");
        if let Err(e) = sess.handshake() {
            error!("SSH 握手失败: {}", e);
            return Err(anyhow!("SSH 握手失败: {}", e));
        }
        info!("SSH 握手成功完成");
        
        // Log the key paths and verify they exist
        let private_key = &self.key_path;
        let public_key = self.key_path.with_extension("pub");
        
        info!("使用私钥文件: {:?}", private_key);
        if !private_key.exists() {
            error!("私钥文件未找到: {:?}", private_key);
            return Err(anyhow!("私钥文件未找到: {:?}", private_key));
        }
        
        info!("使用公钥文件: {:?}", public_key);
        if !public_key.exists() {
            error!("公钥文件未找到: {:?}", public_key);
            return Err(anyhow!("公钥文件未找到: {:?}", public_key));
        }
        
        // Authenticate with the private key
        info!("正在尝试使用密钥对用户 '{}' 进行认证", self.username);
        match sess.userauth_pubkey_file(
            &self.username,
            Some(&public_key),
            private_key,
            None,
        ) {
            Ok(_) => info!("密钥认证成功"),
            Err(e) => {
                error!("密钥认证失败: {}", e);
                return Err(anyhow!("SSH 密钥认证失败: {}。请确保已将公钥添加到用户 {} 的 authorized_keys 文件中", e, self.username));
            }
        }
        
        if !sess.authenticated() {
            error!("SSH 会话未认证，即使没有报告错误");
            return Err(anyhow!("SSH 认证失败: 会话未认证"));
        }
        
        info!("成功连接到 {}:{}", self.host, self.port);
        self.session = Some(Arc::new(Mutex::new(sess)));
        
        Ok(())
    }

    pub async fn forward_remote_port(&self, remote_port: u16, ssh_server: SshServer, _remote_host: String) -> Result<()> {
        if self.session.is_none() {
            return Err(anyhow!("未连接到 SSH 服务器"));
        }

        let session_arc = self.session.as_ref().unwrap().clone();
        
        // Start a background task to handle remote port forwarding
        tokio::spawn(async move {
            let listener = TcpListener::bind(format!("0.0.0.0:{}", remote_port)).await.unwrap();
            info!("正在监听端口 {} 上的 SSH 连接", remote_port);
            
            loop {
                match listener.accept().await {
                    Ok((remote_stream, remote_addr)) => {
                        info!("接受来自 {} 的连接", remote_addr);
                        
                        // Clone resources for the new connection
                        let session_clone = session_arc.clone();
                        let ssh_server_clone = ssh_server.clone();
                        
                        // Handle this connection in a separate task
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(remote_stream, ssh_server_clone, session_clone).await {
                                error!("处理连接时出错: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("接受连接时出错: {}", e);
                        break;
                    }
                }
            }
        });
        
        info!("端口转发已建立: {}:{} -> 本地 SSH 服务器", self.host, remote_port);
        
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