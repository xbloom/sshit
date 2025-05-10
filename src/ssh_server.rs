use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;

use anyhow::Result;
use log::{debug, error, info};
use tokio::sync::Mutex;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId};

/// SSH Server Configuration
#[derive(Clone)]
pub struct SshServerConfig {
    /// Address to listen on
    pub listen_addr: String,
    /// Port to listen on
    pub listen_port: u16,
    /// Path to the server's private key
    #[allow(dead_code)]
    pub key_path: Option<String>,
    /// Default username for authentication
    pub default_username: String,
    /// Default password for authentication
    pub default_password: String,
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
    #[allow(dead_code)]
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
}

impl russh::server::Server for SshServer {
    type Handler = Self;
    
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        let mut s = self.clone();
        s.id = self.id;
        self.id += 1;
        s
    }
    
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("会话错误: {}", error);
    }
}

impl russh::server::Handler for SshServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        info!("用户 {} 尝试无密码认证", user);
        // Only accept if username matches the default
        if user == self.config.default_username {
            info!("用户 {} 无密码认证成功", user);
            return Ok(Auth::Accept);
        }
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!("用户 {} 尝试使用密码进行认证", user);
        
        // Check if username and password match the defaults
        if user == self.config.default_username && password == self.config.default_password {
            info!("用户 {} 密码认证成功", user);
            return Ok(Auth::Accept);
        }
        
        info!("用户 {} 密码认证失败", user);
        Ok(Auth::reject())
    }

    async fn auth_publickey(&mut self, user: &str, _public_key: &russh::keys::ssh_key::PublicKey) -> Result<Auth, Self::Error> {
        info!("用户 {} 尝试使用公钥认证", user);
        Ok(Auth::reject())
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        info!("会话通道已打开");
        let mut clients = self.clients.lock().await;
        clients.insert(self.id, (channel.id(), session.handle()));
        Ok(true)
    }
    
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("收到终端请求: {} ({}x{})", term, col_width, row_height);
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        info!("收到 shell 请求");
        
        // Use the command handler
        if let Some((_, ch)) = self.clients.lock().await.get(&self.id).cloned() {
            let cmd_handler = crate::command_handler::CommandHandler::default();
            
            tokio::spawn(async move {
                if let Err(e) = cmd_handler.start_shell(channel, ch).await {
                    error!("启动 shell 失败: {}", e);
                }
            });
        }
        
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(command).to_string();
        info!("收到执行命令请求: {}", cmd);
        
        // Use the command handler
        if let Some((_, session)) = self.clients.lock().await.get(&self.id).cloned() {
            let cmd_handler = crate::command_handler::CommandHandler::default();
            
            tokio::spawn(async move {
                if let Err(e) = cmd_handler.execute_command(cmd, channel, session).await {
                    error!("执行命令失败: {}", e);
                }
            });
        }
        
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("窗口大小更改请求: {}x{}", col_width, row_height);
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn data(&mut self, channel: ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        debug!("在通道 {} 上收到数据: {:?}", channel, data);
        
        // If received Ctrl+C, disconnect
        if data == [3] {
            return Err(russh::Error::Disconnect.into());
        }
        
        Ok(())
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
} 