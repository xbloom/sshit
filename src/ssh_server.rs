use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;

use anyhow::Result;
use log::{debug, error, info};
use tokio::sync::Mutex;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId, CryptoVec};
use async_trait::async_trait;

/// SSH Server Configuration
#[derive(Clone)]
pub struct SshServerConfig {
    /// Address to listen on
    pub listen_addr: String,
    /// Port to listen on
    pub listen_port: u16,
    /// Path to the server's private key
    pub key_path: Option<String>,
}

/// SSH Server implementation
#[derive(Clone)]
pub struct SshServer {
    pub config: SshServerConfig,
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

impl SshServer {
    /// Create a new SSH server with the given configuration
    pub fn new(config: SshServerConfig) -> Self {
        SshServer {
            config,
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        }
    }

    /// Run the SSH server
    pub async fn run(&mut self) -> Result<()> {
        // Either load the key from the specified path or generate a random one
        let server_key = if let Some(key_path) = &self.config.key_path {
            info!("从 {} 加载 SSH 服务器密钥", key_path);
            let key_path = Path::new(key_path);
            if key_path.exists() {
                match std::fs::read_to_string(key_path) {
                    Ok(key_data) => {
                        russh::keys::PrivateKey::from_openssh(&key_data)?
                    },
                    Err(e) => {
                        error!("读取密钥文件失败: {}", e);
                        return Err(anyhow::anyhow!("读取 SSH 服务器密钥文件失败: {}", e));
                    }
                }
            } else {
                error!("SSH 服务器密钥文件未找到: {}", key_path.display());
                return Err(anyhow::anyhow!("SSH 服务器密钥文件未找到"));
            }
        } else {
            info!("生成随机 SSH 服务器密钥");
            // 使用随机数生成器
            russh::keys::PrivateKey::random(&mut rand::thread_rng(), russh::keys::Algorithm::Ed25519)?
        };

        let config = russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            keys: vec![server_key],
            ..Default::default()
        };

        let config = Arc::new(config);
        let socket_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("在 {} 上启动 SSH 服务器", socket_addr);
        
        // 使用 clone 后的 self 来避免可变借用冲突
        let mut server = self.clone();
        server.run_on_address(config, (self.config.listen_addr.as_str(), self.config.listen_port)).await?;
        
        Ok(())
    }
    
    /// Get the configured listen address
    pub fn get_listen_addr(&self) -> &str {
        &self.config.listen_addr
    }
    
    /// Get the configured listen port
    pub fn get_listen_port(&self) -> u16 {
        self.config.listen_port
    }
}

impl russh::server::Server for SshServer {
    type Handler = SshHandler;
    
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        let id = self.id;
        self.id += 1;
        SshHandler {
            clients: self.clients.clone(),
            id,
        }
    }
    
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("会话错误: {}", error);
    }
}

/// Handler for SSH client sessions
#[derive(Clone)]
pub struct SshHandler {
    clients: Arc<Mutex<HashMap<usize, (ChannelId, russh::server::Handle)>>>,
    id: usize,
}

#[async_trait]
impl russh::server::Handler for SshHandler {
    type Error = anyhow::Error;

    fn auth_none(&mut self, user: &str) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            info!("用户 {} 尝试无密码认证", user);
            Ok(Auth::reject())
        }
    }

    fn auth_password(&mut self, user: &str, password: &str) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            info!("用户 {} 尝试使用密码: {} 进行认证", user, password);
            Ok(Auth::reject())
        }
    }

    fn auth_publickey(&mut self, user: &str, _public_key: &russh::keys::ssh_key::PublicKey) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            info!("用户 {} 尝试使用公钥认证", user);
            Ok(Auth::reject())
        }
    }

    fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async move {
            info!("会话通道已打开");
            let mut clients = self.clients.lock().await;
            clients.insert(self.id, (channel.id(), session.handle()));
            Ok(true)
        }
    }
    
    fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        async move {
            debug!("在通道 {} 上收到数据: {:?}", channel, data);
            // 如果收到 Ctrl+C 则断开连接
            if data == [3] {
                return Err(russh::Error::Disconnect.into());
            }

            let data = CryptoVec::from(format!("回显: {}\r\n", String::from_utf8_lossy(data)));
            // post数据需要单独处理因为self已经被借用
            {
                let mut clients = self.clients.lock().await;
                for (id, (ch, ref mut s)) in clients.iter_mut() {
                    if *id != self.id {
                        let _ = s.data(*ch, data.clone()).await;
                    }
                }
            }
            session.data(channel, data)?;
            Ok(())
        }
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
} 