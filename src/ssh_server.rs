use std::path::Path;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use bytes::Bytes;
use russh_sftp::protocol::Packet;
use tokio::sync::Mutex;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};

use tracing::{error, info, warn};

// 添加对sftp_handler的引用
use crate::sftp_handler::{SftpHandler, SFTP_CHANNELS};

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
    /// SFTP 子系统的工作目录，如果为 None，则使用当前目录
    pub sftp_root_dir: Option<String>,
}

/// 终端信息
#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
}

/// 会话信息，主要用于存储 PTY 相关数据
#[derive(Clone)]
struct SessionInfo {
    /// 通道ID
    #[allow(dead_code)]
    channel_id: ChannelId,
    /// 会话句柄 - 主要用于在无法直接获取会话的异步任务中访问会话
    _handle: russh::server::Handle,
    /// PTY信息，如果会话请求了PTY则有值
    pty_info: Option<PtyInfo>,
    /// 会话创建时间
    #[allow(dead_code)]
    created_at: Instant,
}

/// SSH Server implementation
#[derive(Clone)]
pub struct SshServer {
    /// 服务器配置
    pub config: SshServerConfig,
    /// 会话信息存储
    sessions: Arc<Mutex<HashMap<usize, SessionInfo>>>,
    /// 会话ID生成器
    next_id: Arc<AtomicUsize>,
    /// 当前处理器所属的会话ID
    id: usize,
    /// 命令处理器
    cmd_handler: Arc<crate::command_handler::CommandHandler>,
    /// 通道存储，用于SFTP和其他子系统
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl SshServer {
    /// Create a new SSH server with the given configuration
    pub fn new(config: SshServerConfig) -> Self {
        // 如果配置中有 SFTP 工作目录，验证它是否存在并是否可访问
        if let Some(ref sftp_dir) = config.sftp_root_dir {
            let path = std::path::Path::new(sftp_dir);
            if !path.exists() {
                tracing::warn!(dir = %sftp_dir, "SFTP 工作目录不存在，将使用当前目录");
            } else if !path.is_dir() {
                tracing::warn!(dir = %sftp_dir, "SFTP 工作目录不是一个目录，将使用当前目录");
            } else {
                tracing::info!(dir = %sftp_dir, "使用指定的 SFTP 工作目录");
            }
        }
        
        SshServer {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicUsize::new(0)),
            id: 0,
            cmd_handler: Arc::new(crate::command_handler::CommandHandler::default()),
            channels: Arc::new(Mutex::new(HashMap::new())),
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

    /// 获取当前会话信息 - 仅在需要访问 PTY 信息时使用
    /// 在大多数情况下，应该直接使用传入的 session 参数的 handle() 方法获取会话句柄
    async fn get_session(&self) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().await;
        sessions.get(&self.id).cloned()
    }

    /// 更新会话的PTY信息
    async fn update_pty_info(&self, pty_info: PtyInfo) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        
        sessions.get_mut(&self.id)
            .map(|session| {
                session.pty_info = Some(pty_info);
                Ok(())
            })
            .unwrap_or_else(|| Err(anyhow::anyhow!("找不到会话信息")))
    }

    /// 获取会话的PTY信息
    async fn get_pty_info(&self) -> Option<PtyInfo> {
        self.get_session().await.and_then(|session| session.pty_info)
    }

    /// 获取通道用于SFTP子系统
    async fn get_channel(&self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        let mut clients = self.channels.lock().await;
        clients.remove(&channel_id)
    }

    /// 创建一个 SFTP 处理器，如果配置了工作目录，则设置工作目录
    async fn create_sftp_handler(&self) -> SftpHandler {
        // 创建基本的 SFTP 处理器
        let handler = SftpHandler::default();
        
        // 如果配置了 SFTP 工作目录，设置工作目录
        if let Some(ref sftp_dir) = self.config.sftp_root_dir {
            // 验证目录是否存在并可访问
            let path = std::path::Path::new(sftp_dir);
            if path.exists() && path.is_dir() {
                // 尝试切换到该目录
                if let Err(e) = std::env::set_current_dir(path) {
                    tracing::error!(dir = %sftp_dir, error = %e, "无法切换到 SFTP 工作目录，将使用当前目录");
                } else {
                    tracing::info!(dir = %sftp_dir, "已切换到 SFTP 工作目录");
                }
            }
        }
        
        handler
    }
}

impl russh::server::Server for SshServer {
    type Handler = Self;
    
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        // 使用原子操作获取唯一ID
        let client_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        
        // 创建新的处理器实例，每个客户端用自己的ID
        let mut handler = self.clone();
        handler.id = client_id;
        
        // 为每个新连接创建独立的命令处理器实例
        handler.cmd_handler = Arc::new(crate::command_handler::CommandHandler::default());
        
        tracing::info!(client_id = client_id, "新客户端连接");
        handler
    }
    
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("会话错误: {}", error);
    }
}

impl russh::server::Handler for SshServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let  _ = tracing::info_span!("ssh_auth", session_id = self.id, auth_type = "none", username = %user).entered();
        
        tracing::info!("用户尝试无密码认证");
        
        // Only accept if username matches the default
        if user == self.config.default_username {
            tracing::info!("无密码认证成功");
            return Ok(Auth::Accept);
        }
        
        tracing::warn!("无密码认证被拒绝");
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // 使用tracing进行结构化日志记录
        tracing::info!(
            username = %user, 
            auth_type = "password", 
            "用户尝试密码认证"
        );
        
        // Check if username and password match the defaults
        if password == self.config.default_password {
        // if user == self.config.default_username && password == self.config.default_password {
            tracing::info!(username = %user, "密码认证成功");
            return Ok(Auth::Accept);
        }
        
        tracing::warn!(
            username = %user, 
            success = false, 
            "密码认证失败"
        );
        Ok(Auth::reject())
    }

    async fn auth_publickey(&mut self, user: &str, _public_key: &russh::keys::ssh_key::PublicKey) -> Result<Auth, Self::Error> {
        info!("用户 {} 尝试使用公钥认证", user);
        Ok(Auth::reject())
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        // 使用span记录会话生命周期
        let span = tracing::info_span!(
            "ssh_session", 
            session_id = self.id, 
            channel_id = ?channel.id()
        );
        let _guard = span.enter();
        
        tracing::info!("会话通道已打开");
        
        // 保存会话信息
        {
            let mut sessions = self.sessions.lock().await;
            
            // 记录是否更新了现有会话
            if sessions.contains_key(&self.id) {
                tracing::warn!("已存在会话信息，更新为新会话");
            }
            
            // 插入或更新会话信息
            sessions.insert(self.id, SessionInfo {
                channel_id: channel.id(),
                _handle: session.handle(),
                pty_info: None,
                created_at: Instant::now(),
            });
            
            tracing::info!(
                total_sessions = sessions.len(),
                "当前活跃会话数: {}", sessions.len()
            );
        }
        
        // 保存通道用于子系统请求
        {
            let mut clients = self.channels.lock().await;
            clients.insert(channel.id(), channel);
        }
        
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
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::info!(
            terminal = %term,
            cols = col_width,
            rows = row_height,
            "收到终端请求"
        );
        
        // 1. 验证终端类型
        if !is_valid_terminal_type(term) {
            tracing::warn!(
                terminal = %term,
                channel = ?channel,
                "不支持的终端类型"
            );
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 2. 验证终端大小
        if !is_valid_terminal_size(col_width, row_height) {
            tracing::warn!(
                cols = col_width, 
                rows = row_height,
                channel = ?channel,
                "无效的终端大小"
            );
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 3. 保存PTY信息
        let pty_info = PtyInfo {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
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
        let pty_info = self.get_pty_info().await;
        
        // 获取会话句柄
        let session_handle = session.handle();
        
        // 3. 启动shell - 使用独立的命令处理器
        // 如果没有PTY信息，使用默认值或非交互模式
        if let Some(pty_info) = pty_info {
            // 有PTY信息，使用交互式shell
            match self.cmd_handler.start_shell(
                channel,
                session_handle,
                &pty_info.term,
                pty_info.cols,
                pty_info.rows,
            ).await {
                Ok(_) => {
                    info!("交互式Shell启动成功");
                    session.channel_success(channel)?;
                },
                Err(e) => {
                    error!("启动交互式shell失败: {}", e);
                    session.channel_failure(channel)?;
                }
            }
        } else {
            // 没有PTY信息，使用非交互式shell
            match self.cmd_handler.start_non_interactive_shell(
                channel,
                session_handle,
            ).await {
                Ok(_) => {
                    info!("非交互式Shell启动成功");
                    session.channel_success(channel)?;
                },
                Err(e) => {
                    error!("启动非交互式shell失败: {}", e);
                    session.channel_failure(channel)?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(command).to_string();
        
        
        info!("收到执行命令请求: '{}'", cmd);
        
        // 获取会话句柄用于命令执行
        let session_handle = session.handle();
        
        // 发送成功响应
        session.channel_success(channel)?;
        
        // 使用cmd_handler执行命令
        let cmd_handler = self.cmd_handler.clone();
        
        // 这里仍然可以使用tokio::spawn，因为执行命令不需要等待结果
        tokio::spawn(async move {
            if let Err(e) = cmd_handler.execute_command(cmd, channel, session_handle).await {
                error!("执行命令失败: {}", e);
            }
        });
        
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
        
        // 获取会话句柄
        let session_handle = session.handle();
        
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
            
            // 3. 调整PTY大小 - 使用命令处理器
            if let Err(e) = self.cmd_handler.resize_pty(
                channel, 
                session_handle,
                col_width,
                row_height,
            ).await {
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
    
    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        tracing::trace!("在通道 {} 上收到数据: {:?}", channel, data);
        
        // 首先检查是否是SFTP通道
        if let Ok(sftp_channels) = SFTP_CHANNELS.lock() {
            if sftp_channels.contains(&(self.id, channel)) {
                // 这是一个SFTP通道，直接返回，不处理数据
                // 数据将通过通道流传递给SFTP处理程序
                tracing::debug!(session_id = self.id, channel_id = ?channel, "SFTP接手通道数据，跳过");
                return Ok(());
            }
        }
        
        // 获取会话句柄
        let session_handle = session.handle();
        
        // 1. 处理特殊控制字符
        if data == [3] { // Ctrl+C
            if let Err(e) = self.cmd_handler.send_signal(
                channel, session_handle.clone(), "SIGINT",
            ).await {
                error!("发送SIGINT信号失败: {}", e);
            }
            return Ok(());
        }
        
        // 检查是否为SFTP数据包 (直接使用库解析)
        if data.len() >= 5 {
            // 只进行长度有效性检查，避免明显无效的包
            let packet_len = ((data[0] as u32) << 24) | ((data[1] as u32) << 16) | 
                            ((data[2] as u32) << 8) | (data[3] as u32);
            
            if packet_len > 0 && packet_len < 10*1024*1024 {
                // 将数据转为Bytes尝试解析
                let mut bytes = Bytes::copy_from_slice(data);
                
                // 尝试使用库的Packet解析功能
                match Packet::try_from(&mut bytes) {
                    Ok(packet) => {
                        // 成功解析为SFTP包，注册通道
                        if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
                            sftp_channels.insert((self.id, channel));
                            
                            // 直接记录整个packet内容
                            tracing::info!(
                                session_id = self.id,
                                channel_id = ?channel,
                                "SFTP包: {:?}", packet
                            );
                        }
                        return Ok(());
                    },
                    Err(_) => {
                        // 解析失败，不是SFTP包，继续处理
                    }
                }
            }
        }
        
        // 2. 转发数据到shell - 使用命令处理器
        if let Err(e) = self.cmd_handler.handle_user_input(
            channel, data, session_handle,
        ).await {
            error!("处理用户输入失败: {}", e);
        }
        
        Ok(())
    }

    // channel_eof
    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        tracing::info!("通道 {} 收到EOF", channel);
        // 发送退出状态
        let _ = session.exit_status_request(channel, 0).unwrap();
        Ok(())
    }

    // 添加会话关闭时的处理方法
    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        let span = tracing::info_span!(
            "ssh_session_close", 
            session_id = self.id, 
            channel_id = ?channel
        );
        let _guard = span.enter();
        
        tracing::info!("客户端关闭通道");
        
        // 检查是否是SFTP通道，如果是则移除
        if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
            if sftp_channels.remove(&(self.id, channel)) {
                tracing::info!(session_id = self.id, channel_id = ?channel, "关闭SFTP通道");
            }
        }
        
        // 在实际的会话终止时清理，此处不需操作
        // 实际的清理由Drop trait或会话监控处理
        
        Ok(())
    }

    // 处理子系统请求
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let subsystem_span = tracing::info_span!(
            "收到子系统请求", 
            session_id = self.id,
            channel_id = ?channel_id, 
            subsystem = %name
        );
        let _guard = subsystem_span.enter();
        
        // 目前仅支持SFTP子系统
        if name.to_lowercase() != "sftp" {
            tracing::warn!("不支持的子系统请求");
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        
        // 注册SFTP通道
        if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
            sftp_channels.insert((self.id, channel_id));
            tracing::info!(session_id = self.id, "已注册SFTP通道");
        }
        
        // 获取通道
        let channel = match self.get_channel(channel_id).await {
            Some(channel) => channel,
            None => {
                tracing::error!("找不到对应的通道");
                session.channel_failure(channel_id)?;
                return Ok(());
            }
        };
        
        // 通知客户端成功
        session.channel_success(channel_id)?;
        
        // 准备SFTP服务
        let handler = self.create_sftp_handler().await;
        // let session_handle = session.handle();
        let session_id = self.id;
        
        // 保存原始工作目录
        let original_dir = std::env::current_dir().ok();
        
        // 启动SFTP服务
        tokio::spawn(async move {
            let sftp_span = tracing::info_span!("sftp_session", session_id = session_id, channel_id = ?channel_id);
            let _guard = sftp_span.enter();
            
            tracing::info!("启动SFTP服务");
            
            // 运行SFTP服务
            let channel_stream = channel.into_stream();
            russh_sftp::server::run(channel_stream, handler).await;
            
            tracing::info!("SFTP会话结束");

            //sleep 5 seconds
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            
            // // 发送退出状态
            // let _ = session_handle.exit_status_request(channel_id, 0).await;
            
            // // 注销SFTP通道
            // if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
            //     sftp_channels.remove(&(session_id, channel_id));
            //     tracing::info!(session_id = session_id, channel_id = ?channel_id, "已注销SFTP通道");
            // }
            
            // 恢复原始工作目录
            if let Some(dir) = original_dir {
                if let Err(e) = std::env::set_current_dir(&dir) {
                    tracing::warn!(dir = ?dir, error = %e, "无法恢复原始工作目录");
                } else {
                    tracing::debug!(dir = ?dir, "已恢复原始工作目录");
                }
            }
        });
        
        Ok(())
    }

    // Add the tcpip_forward method implementation to support SOCKS proxying
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::info!(
            address = %address,
            port = %port,
            "收到端口转发请求 (可能是动态端口转发 -D)"
        );
        
        // 始终接受转发请求
        // 如果是动态端口转发（SOCKS代理），客户端将使用 direct-tcpip 通道发起请求
        Ok(true)
    }

    // Handle cancellation of TCP/IP forwarding
    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::info!(
            address = %address,
            port = %port,
            "收到取消端口转发请求"
        );
        
        // 总是接受取消请求
        Ok(true)
    }

    // Handle direct-tcpip channels for SOCKS proxy connections
    async fn channel_open_direct_tcpip(
        &mut self, 
        channel: Channel<Msg>,
        target_host: &str,
        target_port: u32,
        originator_ip: &str,
        originator_port: u32,
        _session: &mut Session
    ) -> Result<bool, Self::Error> {
        tracing::info!(
            target = %format!("{}:{}", target_host, target_port),
            originator = %format!("{}:{}", originator_ip, originator_port),
            "收到直接TCP/IP通道请求 (可能是SOCKS代理连接)"
        );

        // Spawn a task to handle the SOCKS connection
        let channel_stream = channel.into_stream();
        let target = (target_host.to_string(), target_port as u16);
        let target_host = target_host.to_string(); // Clone the string for the async task
        
        tokio::spawn(async move {
            match tokio::net::TcpStream::connect(target).await {
                Ok(target_stream) => {
                    tracing::info!(
                        target = %format!("{}:{}", target_host, target_port),
                        "成功连接到目标主机"
                    );
                    
                    // 连接SSH通道和目标TCP流
                    let (mut channel_reader, mut channel_writer) = tokio::io::split(channel_stream);
                    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
                    
                    // 从SSH通道读取，写入目标
                    let t1 = tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut channel_reader, &mut target_writer).await;
                    });
                    
                    // 从目标读取，写入SSH通道
                    let t2 = tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut target_reader, &mut channel_writer).await;
                    });
                    
                    // 等待任一方向的数据传输结束
                    tokio::select! {
                        _ = t1 => (),
                        _ = t2 => (),
                    }
                    
                    tracing::info!(
                        target = %format!("{}:{}", target_host, target_port),
                        "TCP/IP连接已关闭"
                    );
                },
                Err(e) => {
                    tracing::error!(
                        target = %format!("{}:{}", target_host, target_port),
                        error = %e,
                        "连接目标主机失败"
                    );
                }
            }
        });
        
        // 接受通道打开请求
        Ok(true)
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let id = self.id;
        let sessions = self.sessions.clone();
        
        tokio::spawn(async move {
            let mut sessions = sessions.lock().await;
            if sessions.remove(&id).is_some() {
                tracing::info!(session_id = id, "清理会话ID");
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

