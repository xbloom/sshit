use std::process::Stdio;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use log::{info, error};
use tokio::process::{Command, Child};
use tokio::io::AsyncReadExt;
use russh::CryptoVec;
use russh::ChannelId;
use russh::server::Handle;

/// 命令执行器接口，负责命令的实际执行
#[async_trait]
pub trait CommandExecutor: Send + Sync {
    /// 执行单个命令
    async fn execute_command(&self, command: &str) -> Result<Child, anyhow::Error>;
    
    /// 启动一个Shell
    async fn start_shell(&self) -> Result<Child, anyhow::Error>;
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
    
    async fn start_shell(&self) -> Result<Child, anyhow::Error> {
        Command::new("sh")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("无法启动 shell: {}", e))
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

/// Handler for command execution in SSH server
pub struct CommandHandler {
    command_executor: Arc<dyn CommandExecutor>,
    channel_communicator_factory: Box<dyn Fn(Handle) -> Arc<dyn ChannelCommunicator> + Send + Sync>,
}

impl Default for CommandHandler {
    fn default() -> Self {
        Self {
            command_executor: Arc::new(DefaultCommandExecutor),
            channel_communicator_factory: Box::new(|handle| {
                Arc::new(SshChannelCommunicator::new(handle))
            }),
        }
    }
}

impl CommandHandler {
    /// 创建一个新的命令处理器实例，使用自定义的执行器
    pub fn new(
        command_executor: Arc<dyn CommandExecutor>,
        channel_communicator_factory: Box<dyn Fn(Handle) -> Arc<dyn ChannelCommunicator> + Send + Sync>,
    ) -> Self {
        Self {
            command_executor,
            channel_communicator_factory,
        }
    }
    
    /// 启动一个Shell并连接到SSH通道
    pub async fn start_shell(&self, channel_id: ChannelId, session_handle: Handle) -> Result<(), anyhow::Error> {
        // 使用策略模式创建执行器和通信器
        let communicator = (self.channel_communicator_factory)(session_handle.clone());
        
        // 启动shell进程
        let mut child = self.command_executor.start_shell().await?;
        
        // 设置从shell到SSH客户端的stdout转发
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
        
        // 设置从shell到SSH客户端的stderr转发
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
        
        // 发送欢迎消息
        let welcome_msg = "欢迎使用 SSH 终端！\r\n$ ".as_bytes();
        if let Err(e) = communicator.send_data(channel_id, welcome_msg).await {
            error!("发送欢迎消息失败: {:?}", e);
        }
        
        // 处理shell进程终止并关闭通道
        let communicator_clone = communicator.clone();
        
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => {
                    info!("Shell 进程已终止，状态: {:?}", status);
                    // 发送退出状态
                    let exit_code = status.code().unwrap_or(0) as u32;
                    let _ = communicator_clone.send_exit_status(channel_id, exit_code).await;
                    // 关闭通道
                    let _ = communicator_clone.close_channel(channel_id).await;
                }
                Err(e) => {
                    error!("等待 shell 进程时出错: {}", e);
                    let _ = communicator_clone.close_channel(channel_id).await;
                }
            }
        });
        
        Ok(())
    }
    
    /// 执行单个命令并通过SSH通道返回结果
    pub async fn execute_command(&self, command: String, channel_id: ChannelId, session_handle: Handle) -> Result<(), anyhow::Error> {
        info!("执行命令: {}", command);
        
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
        output: impl tokio::io::AsyncRead + Unpin,
        channel_id: ChannelId,
        communicator: Arc<dyn ChannelCommunicator>,
        is_extended: bool,
        ext_type: u32,
    ) {
        let mut reader = tokio::io::BufReader::new(output);
        let mut buffer = [0; 1024];
        
        loop {
            match reader.read(&mut buffer).await {
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

// 为了向后兼容，提供默认构造函数
impl CommandHandler {
    pub fn new_default() -> Self {
        Self::default()
    }
}

// 让CommandHandler具有默认实现，方便测试代码迁移
impl From<()> for CommandHandler {
    fn from(_: ()) -> Self {
        Self::default()
    }
} 