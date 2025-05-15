use anyhow::{Result, anyhow};
use tracing::{info, error, debug, trace};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use russh::*;
use russh::client;
use russh::client::Handle;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};

use crate::try_log;

// SSH 客户端处理程序
struct ClientHandler {
    local_host: String,
    local_port: u16,
}

impl ClientHandler {
    fn new(local_host: String, local_port: u16) -> Self {
        Self {
            local_host,
            local_port,
        }
    }
}

// 实现 russh 的客户端处理程序特质
impl client::Handler for ClientHandler {
    type Error = russh::Error;
    
    // 校验服务器公钥 (简化版，实际应用中应当记住并验证远程主机的指纹)
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // 在实际应用中，应该验证服务器密钥以防止中间人攻击
        debug!("收到服务器公钥校验请求");
        // 简单起见，这里总是返回 true
        Ok(true)
    }
    
    // 处理从远程服务器打开的转发连接
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        info!("收到远程转发连接: {}:{} -> {}:{} (来自 {}:{})",
              connected_address, connected_port, self.local_host, self.local_port, 
              originator_address, originator_port);
        
        // 启动新任务处理这个连接
        let local_host = self.local_host.clone();
        let local_port = self.local_port;
        
        tokio::spawn(async move {
            // 连接到本地 SSH 服务器
            match TcpStream::connect(format!("{}:{}", local_host, local_port)).await {
                Ok(local_stream) => {
                    if let Err(e) = handle_forwarded_connection(channel, local_stream).await {
                        error!("处理转发连接失败: {}", e);
                    }
                },
                Err(e) => {
                    error!("连接本地 SSH 服务器失败: {}", e);
                    // 关闭通道，向客户端报告错误
                    if let Err(e) = channel.close().await {
                        error!("关闭通道失败: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }
}

// 为 R-SSH 客户端提供一个便于使用的包装
pub struct SshClient {
    host: String,
    port: u16,
    username: String,
    key_path: PathBuf,
    session: Option<Handle<ClientHandler>>,
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

    // New combined method that connects and sets up port forwarding in one step
    pub async fn connect_and_forward(&mut self, remote_port: u16, to_host: String, to_port: u16) -> Result<()> {
        
        // Create connection handler with the correct local host information directly
        let handler = ClientHandler::new(to_host.clone(), to_port);
        
        // 加载私钥
        info!("正在加载密钥 {:?}", self.key_path);
        let start = std::time::Instant::now();
        let key_pair = match load_secret_key(&self.key_path, None) {
            Ok(key) => {
                debug!("密钥加载完成，耗时 {:?}", start.elapsed());
                key
            },
            Err(e) => {
                error!("加载密钥失败: {}", e);
                return Err(anyhow!("加载密钥失败: {}", e));
            }
        };
        
        // 创建默认的 SSH 客户端配置
        let config_client = client::Config::default();
        trace!("SSH客户端配置详情: {:?}", config_client);
        let config_client = Arc::new(config_client);
        
        // 连接到远程 SSH 服务器
        info!("正在连接远程服务器 {}:{} 使用用户名: '{}'", self.host, self.port, self.username);
        let server_address = format!("{}:{}", self.host, self.port);
        
        // 建立 SSH 连接
        let mut session = client::connect(config_client, server_address, handler).await
            .map_err(|e| anyhow!("连接服务器失败: {}", e))?;
        
        debug!("TCP连接建立成功 - 总耗时: {:?}", start.elapsed());
        // 认证（只认证一次）
        info!("正在使用密钥进行认证...");
        debug!("开始密钥认证 - {}", std::time::Instant::now().elapsed().as_secs_f32());
        let key_arc = Arc::new(key_pair);
        let hash_alg = session.best_supported_rsa_hash().await.ok()
            .and_then(|alg: Option<Option<keys::HashAlg>>| { alg.flatten() });

        let key_with_hash = PrivateKeyWithHashAlg::new(key_arc, hash_alg);
        
        debug!("发送认证请求 - {}", std::time::Instant::now().elapsed().as_secs_f32());
        // 认证流程，只有关键日志
        let auth_result = try_log!(
            session.authenticate_publickey(self.username.clone(), key_with_hash).await,
            "认证失败"
        )?;
        
        if !auth_result.success() {
            error!("密钥认证被拒绝");
            return Err(anyhow!("SSH 密钥认证失败，请检查配置"));
        }
        info!("身份验证成功");

        self.session = Some(session);
        
        // 设置远程端口转发
        let session = self.session.as_mut().unwrap();
        let bind_address = "0.0.0.0";
        
        info!("正在设置远程端口转发: {}:{} -> {}:{}", bind_address, remote_port, to_host, to_port);
        // 发送 tcpip-forward 请求
        debug!("开始设置端口转发 - {}", std::time::Instant::now().elapsed().as_secs_f32());
        let forward_start = std::time::Instant::now();
 
        // 尝试设置端口转发并处理结果
        let port = session.tcpip_forward(bind_address, remote_port as u32).await
            .map_err(|e| {
                error!("设置远程端口转发失败: {}", e);
                anyhow!("设置远程端口转发失败: {}", e)
            })?;
            
        debug!("端口转发设置成功 - 耗时: {:?}", forward_start.elapsed());
        
        // 确定实际使用的端口号（如果返回0，则使用请求的端口）
        let actual_port = if port == 0 { remote_port as u32 } else { port };
        info!("远程端口转发成功建立，端口: {}", actual_port);
        
        // 获取session的所有权用于保活线程
        let session_handle = self.session.take().unwrap();
        tokio::spawn(async move {
            let keep_alive_interval = std::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(keep_alive_interval).await;
                if let Err(e) = session_handle.send_keepalive(false).await {
                    error!("发送保活消息失败: {}", e);
                    break;
                }
                debug!("发送保活消息");
            }
        });
        
        info!("端口转发已建立: 远程 SERVER:{} -> 本地 SSH 服务器 {}:{}", 
               actual_port, to_host, to_port);
              
        Ok(())
    }
}

// 处理一个转发连接，在 SSH 通道和本地 TCP 流之间复制数据
async fn handle_forwarded_connection(
    channel: Channel<client::Msg>,
    local_stream: TcpStream,
) -> Result<()> {
    // 创建异步读取器和写入器
    let (local_reader, local_writer) = tokio::io::split(local_stream);
    
    // 将通道拆分为读和写两部分
    let (mut channel_read, channel_write) = channel.split();
    
    // 从 SSH 通道读取，写入本地连接
    let ssh_to_local_fut = async {
        let mut local_writer = local_writer;
        loop {
            match channel_read.wait().await {
                Some(ChannelMsg::Data { ref data }) => {
                    if let Err(e) = local_writer.write_all(data).await {
                        error!("写入数据到本地连接失败: {}", e);
                        break;
                    }
                },
                Some(ChannelMsg::Eof) => {
                    debug!("SSH 通道发送了 EOF");
                    break;
                },
                Some(ChannelMsg::Close) => {
                    debug!("SSH 通道已关闭");
                    break;
                },
                None => {
                    debug!("SSH 通道已结束");
                    break;
                },
                _ => {} // 忽略其他消息
            }
        }
    };
    
    // 从本地连接读取，写入 SSH 通道
    let local_to_ssh_fut = async {
        let mut local_reader = local_reader;
        let channel_write = channel_write;
        let mut buffer = [0u8; 16384];
        
        loop {
            match local_reader.read(&mut buffer).await {
                Ok(0) => {
                    debug!("本地连接已关闭");
                    if let Err(e) = channel_write.eof().await {
                        error!("发送 EOF 失败: {}", e);
                    }
                    break;
                },
                Ok(n) => {
                    if let Err(e) = channel_write.data(&buffer[..n]).await {
                        error!("发送数据到 SSH 通道失败: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    error!("从本地连接读取失败: {}", e);
                    break;
                }
            }
        }
        
        // 确保通道关闭
        if let Err(e) = channel_write.close().await {
            error!("关闭通道失败: {}", e);
        }
    };
    
    // 等待任一任务完成，直接使用 futures 而不是 JoinHandle
    tokio::select! {
        _ = ssh_to_local_fut => debug!("SSH->本地 数据传输结束"),
        _ = local_to_ssh_fut => debug!("本地->SSH 数据传输结束"),
    }
    
    Ok(())
} 