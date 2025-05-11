use std::process::Stdio;
use std::sync::Arc;
use std::io::{Read, Write};

use anyhow::Result;
use async_trait::async_trait;
use log::{info, error};
use tokio::process::{Command, Child};
use tokio::io::AsyncReadExt;
use russh::CryptoVec;
use russh::ChannelId;
use russh::server::Handle;

// 添加tracing
use tracing;

// 使用portable-pty，移除未使用的PtyPair
use portable_pty::{PtySize, CommandBuilder, native_pty_system, Child as PtyChild, MasterPty};
use std::sync::Mutex as StdMutex;

/// 命令日志记录器，用于收集和记录用户输入的命令
struct CommandLogger {
    /// 命令缓冲区，用于收集用户输入的命令
    cmd_buffer: Arc<tokio::sync::Mutex<String>>,
}

impl CommandLogger {
    /// 创建一个新的命令日志记录器
    fn new() -> Self {
        Self {
            cmd_buffer: Arc::new(tokio::sync::Mutex::new(String::new())),
        }
    }

    /// 处理用户输入，收集命令并在检测到回车键时记录完整命令
    async fn process_input(&self, channel_id: ChannelId, data: &[u8]) {
        // 检查是否包含回车键（ASCII 13）或换行符（ASCII 10）
        let contains_enter = data.iter().any(|&b| b == 13 || b == 10);
        
        // 尝试将输入转换为字符串
        if let Ok(input) = String::from_utf8(data.to_vec()) {
            let mut buffer = self.cmd_buffer.lock().await;
            
            // 如果是退格键（ASCII 127或8），删除缓冲区最后一个字符
            if data.len() == 1 && (data[0] == 127 || data[0] == 8) {
                buffer.pop();
            } else {
                // 否则添加到缓冲区
                buffer.push_str(&input);
            }
            
            // 如果检测到回车键，记录完整命令并清空缓冲区
            if contains_enter {
                // 清理命令字符串，去除控制字符和换行符
                let cmd = buffer.trim_end_matches(|c| c == '\r' || c == '\n')
                    .trim()
                    .to_string();
                
                // 只记录非空命令
                if !cmd.is_empty() {
                    tracing::info!(
                        channel_id = ?channel_id,
                        command = %cmd,
                        "shell执行命令"
                    );
                }
                
                // 清空缓冲区
                buffer.clear();
            }
        }
    }

    /// 记录执行的命令
    fn log_command(channel_id: ChannelId, command: &str) {
        tracing::info!(
            channel_id = ?channel_id,
            command = %command,
            "exec执行命令"
        );
    }
}

impl Clone for CommandLogger {
    fn clone(&self) -> Self {
        Self {
            cmd_buffer: self.cmd_buffer.clone(),
        }
    }
}

/// 命令执行器接口，负责命令的实际执行
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// 执行单个命令
    async fn execute_command(&self, command: &str) -> Result<Child, anyhow::Error>;
        
    /// 启动一个带PTY的Shell
    async fn start_shell_with_pty(&self, term: &str, cols: u32, rows: u32) -> Result<(Arc<StdMutex<Box<dyn MasterPty + Send>>>, Box<dyn PtyChild + Send>), anyhow::Error>;
    
    /// 调整PTY大小
    async fn resize_pty(&self, pty: &Arc<StdMutex<Box<dyn MasterPty + Send>>>, cols: u32, rows: u32) -> Result<(), anyhow::Error>;
    
    /// 发送信号到进程
    async fn send_signal(&self, child: &mut Box<dyn PtyChild + Send>, signal: &str) -> Result<(), anyhow::Error>;
}

/// 通道通信接口，负责与SSH通道的通信
#[async_trait]
pub trait ChannelCommunicator: Send + Sync {
    /// 发送数据到通道
    async fn send_data(&self, channel_id: ChannelId, data: &[u8]) -> Result<(), anyhow::Error>;
    
    /// 发送扩展数据到通道（通常用于stderr）
    async fn send_extended_data(&self, channel_id: ChannelId, ext: u32, data: &[u8]) -> Result<(), anyhow::Error>;
    
    /// 发送退出状态
    async fn send_exit_status(&self, channel_id: ChannelId, exit_status: u32) -> Result<(), anyhow::Error>;
    
    /// 发送EOF
    async fn send_eof(&self, channel_id: ChannelId) -> Result<(), anyhow::Error>;
    
    /// 关闭通道
    async fn close_channel(&self, channel_id: ChannelId) -> Result<(), anyhow::Error>;
}

/// 默认命令执行器实现
pub struct DefaultCommandExecutor;

#[async_trait]
impl CommandExecutor for DefaultCommandExecutor {
    async fn execute_command(&self, command: &str) -> Result<Child, anyhow::Error> {
        Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("无法启动命令: {}", e))
    }
    
    async fn start_shell_with_pty(&self, term: &str, cols: u32, rows: u32) -> Result<(Arc<StdMutex<Box<dyn MasterPty + Send>>>, Box<dyn PtyChild + Send>), anyhow::Error> {
        // 1. 创建PTY系统和调整大小
        let pty_system = native_pty_system();
        let pty_size = PtySize {
            rows: rows as u16,
            cols: cols as u16,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        // 2. 创建PTY对
        let pair = pty_system.openpty(pty_size)
            .map_err(|e| anyhow::anyhow!("创建PTY失败: {}", e))?;
            
        // 3. 创建命令
        let mut cmd = CommandBuilder::new("bash");
        cmd.env("TERM", term);
        // 设置重要的环境变量来确保正确的提示符和交互式体验
        cmd.env("PS1", "\\u@\\h:\\w\\$ ");  // 标准提示符格式
        cmd.env("IUTF8", "1");              // 启用UTF-8输入处理
        
        // 告诉bash使用交互式模式运行
        cmd.arg("-i");
        
        // 4. 启动进程
        let child = pair.slave.spawn_command(cmd)
            .map_err(|e| anyhow::anyhow!("启动Shell - bash进程失败: {}", e))?;
            
        // 5. 将主PTY封装在Arc<Mutex>中，使其可以安全地跨线程共享
        let master = Arc::new(StdMutex::new(pair.master));
            
        Ok((master, child))
    }
    
    async fn resize_pty(&self, pty: &Arc<StdMutex<Box<dyn MasterPty + Send>>>, cols: u32, rows: u32) -> Result<(), anyhow::Error> {
        let pty_size = PtySize {
            rows: rows as u16,
            cols: cols as u16,
            pixel_width: 0,
            pixel_height: 0,
        };
        
        // 获取锁并调整大小
        let master = pty.lock().map_err(|_| anyhow::anyhow!("获取PTY锁失败"))?;
        master.resize(pty_size)
            .map_err(|e| anyhow::anyhow!("调整PTY大小失败: {}", e))
    }
    
    async fn send_signal(&self, child: &mut Box<dyn PtyChild + Send>, signal: &str) -> Result<(), anyhow::Error> {
        // portable-pty支持的信号有限，主要是kill()方法
        match signal {
            "SIGINT" | "SIGTERM" | "SIGKILL" => {
                child.kill()
                    .map_err(|e| anyhow::anyhow!("发送终止信号失败: {}", e))
            },
            _ => Err(anyhow::anyhow!("不支持的信号: {}", signal)),
        }
    }
}

/// SSH通道通信器实现
pub struct SshChannelCommunicator {
    handle: Handle,
}

impl SshChannelCommunicator {
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl ChannelCommunicator for SshChannelCommunicator {
    async fn send_data(&self, channel_id: ChannelId, data: &[u8]) -> Result<(), anyhow::Error> {
        let data_vec = CryptoVec::from_slice(data);
        self.handle.data(channel_id, data_vec)
            .await
            .map_err(|e| anyhow::anyhow!("发送数据失败: {:?}", e))
    }
    
    async fn send_extended_data(&self, channel_id: ChannelId, ext: u32, data: &[u8]) -> Result<(), anyhow::Error> {
        let data_vec = CryptoVec::from_slice(data);
        self.handle.extended_data(channel_id, ext, data_vec)
            .await
            .map_err(|e| anyhow::anyhow!("发送扩展数据失败: {:?}", e))
    }
    
    async fn send_exit_status(&self, channel_id: ChannelId, exit_status: u32) -> Result<(), anyhow::Error> {
        self.handle.exit_status_request(channel_id, exit_status)
            .await
            .map_err(|_| anyhow::anyhow!("发送退出状态失败"))
    }
    
    async fn send_eof(&self, channel_id: ChannelId) -> Result<(), anyhow::Error> {
        self.handle.eof(channel_id)
            .await
            .map_err(|_| anyhow::anyhow!("发送EOF失败"))
    }
    
    async fn close_channel(&self, channel_id: ChannelId) -> Result<(), anyhow::Error> {
        self.handle.close(channel_id)
            .await
            .map_err(|_| anyhow::anyhow!("关闭通道失败"))
    }
}

/// PTY会话信息
struct PtySession {
    master_pty: Arc<StdMutex<Box<dyn MasterPty + Send>>>,
    child: Box<dyn PtyChild + Send>,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    // 添加会话创建时间用于调试
    created_at: std::time::Instant,
}

/// Handler for command execution in SSH server
pub struct CommandHandler {
    command_executor: Arc<dyn CommandExecutor>,
    channel_communicator_factory: Arc<dyn Fn(Handle) -> Arc<dyn ChannelCommunicator> + Send + Sync>,
    // 使用单个会话而不是哈希表
    pty_session: Arc<tokio::sync::Mutex<Option<PtySession>>>,
    // 命令日志记录器
    cmd_logger: CommandLogger,
}

impl Default for CommandHandler {
    fn default() -> Self {
        Self {
            command_executor: Arc::new(DefaultCommandExecutor),
            channel_communicator_factory: Arc::new(|handle| {
                Arc::new(SshChannelCommunicator::new(handle))
            }),
            pty_session: Arc::new(tokio::sync::Mutex::new(None)),
            cmd_logger: CommandLogger::new(),
        }
    }
}

impl CommandHandler {
    /// 创建一个新的命令处理器实例，使用自定义的执行器
    #[allow(dead_code)]
    pub fn new(
        command_executor: Arc<dyn CommandExecutor>,
        channel_communicator_factory: Arc<dyn Fn(Handle) -> Arc<dyn ChannelCommunicator> + Send + Sync>,
    ) -> Self {
        Self {
            command_executor,
            channel_communicator_factory,
            pty_session: Arc::new(tokio::sync::Mutex::new(None)),
            cmd_logger: CommandLogger::new(),
        }
    }
    
    /// 启动一个Shell并连接到SSH通道
    pub async fn start_shell(
        &self,
        channel_id: ChannelId,
        session_handle: Handle,
        term: &str,
        cols: u32,
        rows: u32,
    ) -> Result<(), anyhow::Error> {
        // 使用策略模式创建执行器和通信器
        let communicator = (self.channel_communicator_factory)(session_handle.clone());
        
        // 启动shell进程
        let (master_pty, child) = self.command_executor.start_shell_with_pty(term, cols, rows).await?;
        
        // 创建读取器
        let reader = {
            // 需要在锁的范围内获取reader
            let master = master_pty.lock().map_err(|_| anyhow::anyhow!("获取PTY锁失败"))?;
            master.try_clone_reader()
                .map_err(|e| anyhow::anyhow!("无法克隆PTY读取器: {}", e))?
        };
        
        // 创建写入器 - 注意这里的writer会消耗掉主PTY的写入器，所以不是克隆
        let writer: Box<dyn Write + Send> = {
            let master = master_pty.lock().map_err(|_| anyhow::anyhow!("获取PTY锁失败"))?;
            Box::new(master.take_writer().map_err(|e| anyhow::anyhow!("无法获取PTY写入器: {}", e))?)
        };
            
        // 保存PTY会话
        let mut pty_session = PtySession {
            master_pty: master_pty.clone(),
            child,
            reader: Some(reader),
            writer: Some(writer),
            created_at: std::time::Instant::now(),
        };
        
        // 设置从shell到SSH客户端的输出转发
        let mut reader = pty_session.reader.take().unwrap();
        let communicator_clone = communicator.clone();
        
        tokio::spawn(async move {
            // 创建缓冲区
            let mut buffer = [0u8; 1024];
            loop {
                // 使用标准io::Read，在tokio线程中执行阻塞读取
                match std::io::Read::read(&mut reader, &mut buffer) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        // 使用tokio任务来发送数据，避免阻塞当前线程
                        let data = buffer[..n].to_vec();
                        let communicator = communicator_clone.clone();
                        let channel = channel_id;
                        
                        // 在另一个tokio任务中发送数据 - 使用优先级较高的任务
                        tokio::task::spawn_blocking(move || {
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                if let Err(e) = communicator.send_data(channel, &data).await {
                                    error!("发送数据失败: {:?}", e);
                                }
                            });
                        });
                    }
                    Err(e) => {
                        error!("读取PTY输出失败: {}", e);
                        break;
                    }
                }
            }
            // 读取结束，通知客户端
            tokio::spawn(async move {
                let _ = communicator_clone.send_eof(channel_id).await;
                let _ = communicator_clone.close_channel(channel_id).await;
            });
        });
        
        // 记录日志并保存PTY会话
        tracing::info!(
            channel_id = ?channel_id,
            "保存新的PTY会话"
        );
        
        // 保存会话
        {
            let mut session_lock = self.pty_session.lock().await;
            *session_lock = Some(pty_session);
        }
        
        // 处理shell进程终止并关闭通道
        let communicator_clone = communicator.clone();
        let pty_session_lock = self.pty_session.clone();
        
        tokio::spawn(async move {
            // 定期检查进程是否终止
            let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
            
            loop {
                interval.tick().await;
                
                let mut session_lock = pty_session_lock.lock().await;
                if let Some(session) = session_lock.as_mut() {
                    // 检查进程是否终止
                    if let Some(status) = session.child.try_wait().unwrap_or(None) {
                        info!("Shell 进程已终止，状态: {:?}", status);
                        
                        // 发送退出状态 - portable-pty使用不同的ExitStatus结构
                        // 我们只能获取到一个bool，表示进程是否正常退出
                        let exit_code = if status.success() { 0 } else { 1 };
                        
                        let _ = communicator_clone.send_exit_status(channel_id, exit_code).await;
                        let _ = communicator_clone.send_eof(channel_id).await;
                        let _ = communicator_clone.close_channel(channel_id).await;
                        
                        // 移除会话
                        *session_lock = None;
                        tracing::info!(
                            channel_id = ?channel_id,
                            "会话已终止并清理"
                        );
                        break;
                    }
                } else {
                    // 会话已不存在
                    break;
                }
            }
        });
        
        Ok(())
    }
    
    /// 调整PTY大小
    pub async fn resize_pty(
        &self,
        _channel_id: ChannelId,
        _session_handle: Handle,
        cols: u32,
        rows: u32,
    ) -> Result<(), anyhow::Error> {
        // 获取会话并调整大小
        let session_lock = self.pty_session.lock().await;
        
        if let Some(session) = session_lock.as_ref() {
            self.command_executor.resize_pty(&session.master_pty, cols, rows).await
        } else {
            Err(anyhow::anyhow!("找不到PTY会话"))
        }
    }
    
    /// 发送信号到进程
    pub async fn send_signal(
        &self,
        _channel_id: ChannelId,
        _session_handle: Handle,
        signal: &str,
    ) -> Result<(), anyhow::Error> {
        // 获取会话并发送信号
        let mut session_lock = self.pty_session.lock().await;
        
        if let Some(session) = session_lock.as_mut() {
            self.command_executor.send_signal(&mut session.child, signal).await
        } else {
            Err(anyhow::anyhow!("找不到PTY会话"))
        }
    }
    
    /// 处理用户输入
    pub async fn handle_user_input(
        &self,
        _channel_id: ChannelId,
        data: &[u8],
        _session_handle: Handle,
    ) -> Result<(), anyhow::Error> {
        // 使用命令日志记录器处理用户输入
        self.cmd_logger.process_input(_channel_id, data).await;
        
        // 获取会话
        let mut session_lock = self.pty_session.lock().await;
        
        if let Some(session) = session_lock.as_mut() {
            // 如果writer不存在，这是一个严重错误
            if session.writer.is_none() {
                return Err(anyhow::anyhow!("PTY写入器不可用，无法恢复"));
            }
            
            // 写入数据
            if let Some(writer) = &mut session.writer {
                writer.write_all(data)
                    .map_err(|e| anyhow::anyhow!("写入PTY失败: {}", e))?;
                
                writer.flush()
                    .map_err(|e| anyhow::anyhow!("刷新PTY缓冲区失败: {}", e))?;
            } else {
                return Err(anyhow::anyhow!("PTY写入器不可用"));
            }
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("找不到PTY会话"))
        }
    }
    
    /// 执行单个命令并通过SSH通道返回结果
    pub async fn execute_command(&self, command: String, channel_id: ChannelId, session_handle: Handle) -> Result<(), anyhow::Error> {
        // 使用命令日志记录器记录执行的命令
        CommandLogger::log_command(channel_id, &command);
        
        // 使用策略模式创建通信器
        let communicator = (self.channel_communicator_factory)(session_handle.clone());
        
        // 执行命令
        let mut child = self.command_executor.execute_command(&command).await?;
        
        // 设置stdout/stderr转发到SSH客户端
        if let Some(stdout) = child.stdout.take() {
            let communicator_clone = communicator.clone();
            
            tokio::spawn(async move {
                Self::handle_process_output(
                    stdout,
                    channel_id,
                    communicator_clone,
                    false, // 不是扩展数据
                    0, // 扩展数据类型（不使用）
                ).await;
            });
        }
        
        if let Some(stderr) = child.stderr.take() {
            let communicator_clone = communicator.clone();
            
            tokio::spawn(async move {
                Self::handle_process_output(
                    stderr,
                    channel_id,
                    communicator_clone,
                    true, // 是扩展数据
                    1, // 扩展数据类型（stderr）
                ).await;
            });
        }
        
        // 处理命令完成和退出状态
        let communicator_clone = communicator.clone();
        
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => {
                    info!("命令执行完成，状态: {:?}", status);
                    // 发送退出状态和EOF，然后关闭通道
                    let exit_code = status.code().unwrap_or(0) as u32;
                    let _ = communicator_clone.send_exit_status(channel_id, exit_code).await;
                    let _ = communicator_clone.send_eof(channel_id).await;
                    let _ = communicator_clone.close_channel(channel_id).await;
                }
                Err(e) => {
                    error!("等待命令完成时出错: {}", e);
                    let _ = communicator_clone.close_channel(channel_id).await;
                }
            }
        });
        
        Ok(())
    }
    
    /// 处理进程输出，将其转发到SSH通道
    async fn handle_process_output(
        mut output: impl tokio::io::AsyncRead + Unpin,
        channel_id: ChannelId,
        communicator: Arc<dyn ChannelCommunicator>,
        is_extended: bool,
        ext_type: u32,
    ) {
        let mut buffer = [0; 1024];
        
        loop {
            match output.read(&mut buffer).await {
                Ok(0) => {
                    // EOF - 对于stdout，可能需要发送EOF
                    if !is_extended {
                        let _ = communicator.send_eof(channel_id).await;
                    }
                    break;
                }
                Ok(n) => {
                    // 发送数据
                    let result = if is_extended {
                        communicator.send_extended_data(channel_id, ext_type, &buffer[..n]).await
                    } else {
                        communicator.send_data(channel_id, &buffer[..n]).await
                    };
                    
                    if let Err(e) = result {
                        if is_extended {
                            error!("发送扩展数据失败: {:?}", e);
                        } else {
                            error!("发送数据失败: {:?}", e);
                        }
                        break;
                    }
                }
                Err(e) => {
                    if is_extended {
                        error!("读取子进程错误输出失败: {}", e);
                    } else {
                        error!("读取子进程输出失败: {}", e);
                    }
                    break;
                }
            }
        }
    }
}

// 手动实现Clone
impl Clone for CommandHandler {
    fn clone(&self) -> Self {
        CommandHandler {
            command_executor: self.command_executor.clone(),
            channel_communicator_factory: self.channel_communicator_factory.clone(),
            pty_session: self.pty_session.clone(),
            cmd_logger: self.cmd_logger.clone(),
        }
    }
}

// 让CommandHandler具有默认实现，方便测试代码迁移
impl From<()> for CommandHandler {
    fn from(_: ()) -> Self {
        Self::default()
    }
} 