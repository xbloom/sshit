use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::sync::Mutex;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};

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

/// 终端信息
#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
    modes: Vec<(Pty, u32)>,
}

/// 会话信息，包含所有与客户端会话相关的数据
#[derive(Clone)]
struct SessionInfo {
    /// 通道ID
    channel_id: ChannelId,
    /// 会话句柄
    handle: russh::server::Handle,
    /// PTY信息，如果会话请求了PTY则有值
    pty_info: Option<PtyInfo>,
    /// 会话创建时间
    created_at: Instant,
}

/// SSH Server implementation
#[derive(Clone)]
pub struct SshServer {
    pub config: SshServerConfig,
    /// 所有会话信息
    sessions: Arc<Mutex<HashMap<usize, SessionInfo>>>,
    /// 会话ID计数器
    id: usize,
    /// 命令处理器实例，确保所有PTY操作使用相同的实例
    cmd_handler: Arc<crate::command_handler::CommandHandler>,
}

impl SshServer {
    /// Create a new SSH server with the given configuration
    pub fn new(config: SshServerConfig) -> Self {
        SshServer {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
            cmd_handler: Arc::new(crate::command_handler::CommandHandler::default()),
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

    /// 查找当前会话信息
    async fn get_session(&self) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().await;
        sessions.get(&self.id).cloned()
    }

    /// 更新会话的PTY信息
    async fn update_pty_info(&self, pty_info: PtyInfo) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&self.id) {
            session.pty_info = Some(pty_info);
            Ok(())
        } else {
            Err(anyhow::anyhow!("找不到会话信息"))
        }
    }

    /// 获取会话的PTY信息
    async fn get_pty_info(&self) -> Option<PtyInfo> {
        let sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(&self.id) {
            session.pty_info.clone()
        } else {
            None
        }
    }

    // 新增方法：通过通道ID查找会话
    async fn get_session_by_channel(&self, channel_id: ChannelId) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().await;
        // 遍历所有会话，查找匹配通道ID的会话
        for session in sessions.values() {
            if session.channel_id == channel_id {
                return Some(session.clone());
            }
        }
        None
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
        let mut sessions = self.sessions.lock().await;
        sessions.insert(self.id, SessionInfo {
            channel_id: channel.id(),
            handle: session.handle(),
            pty_info: None,
            created_at: Instant::now(),
        });
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
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("收到终端请求: {} ({}x{})", term, col_width, row_height);
        
        // 1. 验证终端类型
        if !is_valid_terminal_type(term) {
            warn!("不支持的终端类型: {}", term);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 2. 验证终端大小
        if !is_valid_terminal_size(col_width, row_height) {
            warn!("无效的终端大小: {}x{}", col_width, row_height);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 3. 保存PTY信息
        let pty_info = PtyInfo {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
            modes: modes.to_vec(),
        };

        // 更新会话的PTY信息
        if let Err(e) = self.update_pty_info(pty_info).await {
            error!("保存PTY信息失败: {}", e);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 4. 发送成功响应
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        info!("收到 shell 请求");
        
        // 1. 检查是否已经收到PTY请求
        let pty_info = match self.get_pty_info().await {
            Some(info) => info,
            None => {
                warn!("收到shell请求但没有PTY信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        
        // 2. 获取会话信息
        let session_info = match self.get_session().await {
            Some(info) => info,
            None => {
                error!("找不到会话信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        
        // 3. 启动shell - 使用共享的命令处理器
        // 直接await启动shell的结果，而不是异步启动
        match self.cmd_handler.start_shell_with_pty(
            channel,
            session_info.handle,
            &pty_info.term,
            pty_info.cols,
            pty_info.rows,
        ).await {
            Ok(_) => {
                info!("Shell启动成功");
                session.channel_success(channel)?;
            },
            Err(e) => {
                error!("启动shell失败: {}", e);
                session.channel_failure(channel)?;
            }
        }
        
        Ok(())
    }
    
    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(command).to_string();
        info!("收到执行命令请求: '{}'", cmd);
        
        // 获取会话信息
        if let Some(session_info) = self.get_session().await {
            // 发送成功响应
            session.channel_success(channel)?;
            
            // 使用cmd_handler执行命令
            let cmd_handler = self.cmd_handler.clone();
            
            // 这里仍然可以使用tokio::spawn，因为执行命令不需要等待结果
            tokio::spawn(async move {
                if let Err(e) = cmd_handler.execute_command(cmd, channel, session_info.handle.clone()).await {
                    error!("执行命令失败: {}", e);
                }
            });
        } else {
            error!("找不到会话信息");
            session.channel_failure(channel)?;
        }
        
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
        
        // 1. 验证新的终端大小
        if !is_valid_terminal_size(col_width, row_height) {
            warn!("无效的终端大小: {}x{}", col_width, row_height);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 2. 更新PTY信息
        let mut sessions = self.sessions.lock().await;
        if let Some(session_info) = sessions.get_mut(&self.id) {
            if let Some(pty_info) = &mut session_info.pty_info {
                pty_info.cols = col_width;
                pty_info.rows = row_height;
            } else {
                warn!("尝试更新PTY大小，但会话没有PTY信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
            
            // 3. 调整PTY大小 - 使用共享的命令处理器
            if let Err(e) = self.cmd_handler.resize_pty(channel, session_info.handle.clone(), col_width, row_height).await {
                error!("调整PTY大小失败: {}", e);
                session.channel_failure(channel)?;
                return Ok(());
            }
            
            session.channel_success(channel)?;
        } else {
            error!("找不到会话信息");
            session.channel_failure(channel)?;
        }
        
        Ok(())
    }
    
    async fn data(&mut self, channel: ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        debug!("在通道 {} 上收到数据: {:?}", channel, data);
        
        // 获取会话信息
        if let Some(session_info) = self.get_session().await {
            // 1. 处理特殊控制字符
            if data == [3] { // Ctrl+C
                if let Err(e) = self.cmd_handler.send_signal(channel, session_info.handle.clone(), "SIGINT").await {
                    error!("发送SIGINT信号失败: {}", e);
                }
                return Ok(());
            }
            
            // 2. 转发数据到shell - 使用共享的命令处理器
            if let Err(e) = self.cmd_handler.handle_user_input(channel, data, session_info.handle.clone()).await {
                error!("处理用户输入失败: {}", e);
            }
        } else {
            error!("找不到会话信息，无法处理用户输入");
        }
        
        Ok(())
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let id = self.id;
        let sessions = self.sessions.clone();
        
        tokio::spawn(async move {
            let mut sessions = sessions.lock().await;
            if sessions.remove(&id).is_some() {
                debug!("清理会话ID: {}", id);
            }
        });
    }
}

/// 验证终端类型是否有效
fn is_valid_terminal_type(term: &str) -> bool {
    let valid_terms = [
        "xterm", "xterm-256color", "vt100", "vt220",
        "linux", "screen", "screen-256color"
    ];
    valid_terms.contains(&term)
}

/// 验证终端大小是否有效
fn is_valid_terminal_size(cols: u32, rows: u32) -> bool {
    cols > 0 && cols <= 1000 && rows > 0 && rows <= 1000
} 