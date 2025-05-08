use anyhow::{Result, anyhow};
use log::{info, error};
use ssh2::Session;
use std::net::TcpStream;
use std::path::PathBuf;
use std::io::{Read, Write};
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

    pub async fn forward_remote_port(&self, remote_port: u16, ssh_server: SshServer, remote_host: String) -> Result<()> {
        if self.session.is_none() {
            return Err(anyhow!("未连接到 SSH 服务器"));
        }

        let session_arc = self.session.as_ref().unwrap().clone();
        
        // 获取会话的互斥锁
        let session = session_arc.lock().await;
        
        // 设置远程端口转发 (remote_port 将在远程机器上开放，转发到本地 SSH 服务器)
        info!("正在尝试设置远程端口转发: {}:{} -> {}:{}", 
              remote_host, remote_port, ssh_server.local_host, ssh_server.local_port);
              
        // 使用正确的 SSH2 API 设置远程转发
        match session.channel_forward_listen(remote_port, Some(&ssh_server.local_host), None) {
            Ok((mut listener, actual_port)) => {
                info!("远程端口转发成功设置: {}:{} -> {}:{}, 实际端口: {}", 
                      remote_host, remote_port, ssh_server.local_host, ssh_server.local_port, actual_port);
                
                // 释放锁，以便后续操作可以获取锁
                drop(session);
                
                // 启动处理转发连接的后台任务
                let session_for_accept = session_arc.clone();
                let ssh_server_clone = ssh_server.clone();
                
                // 创建一个专门处理转发连接的任务
                tokio::spawn(async move {
                    // 使用阻塞任务处理 SSH2 库的阻塞操作
                    tokio::task::spawn_blocking(move || {
                        // 获取阻塞模式的会话 (我们只需要 listener，实际上不需要使用会话)
                        let _session = session_for_accept.blocking_lock();
                        
                        // 不断接受连接
                        loop {
                            // 阻塞接受连接
                            match listener.accept() {
                                Ok(mut channel) => {
                                    info!("接受到一个转发连接");
                                    
                                    // 为每个连接创建一个新的处理流程
                                    let ssh_server = ssh_server_clone.clone();
                                    
                                    // 连接到本地 SSH 服务器
                                    match TcpStream::connect(format!("{}:{}", ssh_server.local_host, ssh_server.local_port)) {
                                        Ok(mut local_stream) => {
                                            // 配置通道
                                            channel.handle_extended_data(ssh2::ExtendedData::Merge).unwrap_or_else(|e| {
                                                error!("设置扩展数据处理失败: {}", e);
                                            });
                                            
                                            // 建立双向数据流
                                            std::thread::spawn(move || {
                                                // 标准输入输出模式，自动处理数据传输
                                                if channel.request_pty("xterm", None, None).is_ok() {
                                                    info!("连接已建立，正在转发数据");
                                                    
                                                    // 使用简单的 IO 复制来处理数据传输
                                                    let mut buffer = [0; 8192];
                                                    loop {
                                                        // 从通道读取数据并写入本地流
                                                        match channel.read(&mut buffer) {
                                                            Ok(0) => break, // EOF
                                                            Ok(n) => {
                                                                if local_stream.write_all(&buffer[..n]).is_err() {
                                                                    break;
                                                                }
                                                            }
                                                            Err(_) => break,
                                                        }
                                                        
                                                        // 从本地流读取数据并写入通道
                                                        match local_stream.read(&mut buffer) {
                                                            Ok(0) => break, // EOF
                                                            Ok(n) => {
                                                                if channel.write_all(&buffer[..n]).is_err() {
                                                                    break;
                                                                }
                                                            }
                                                            Err(_) => break,
                                                        }
                                                    }
                                                }
                                            });
                                        },
                                        Err(e) => {
                                            error!("连接本地 SSH 服务器失败: {}", e);
                                        }
                                    }
                                },
                                Err(e) => {
                                    // 检查是否是连接超时
                                    error!("接受转发连接失败: {}", e);
                                    if e.to_string().contains("timeout") {
                                        continue;
                                    }
                                    break;
                                }
                            }
                        }
                    });
                });
            },
            Err(e) => {
                error!("设置远程端口转发失败: {}", e);
                return Err(anyhow!("设置远程端口转发失败: {}", e));
            }
        }
        
        // 保持会话活跃以维持端口转发
        tokio::spawn(async move {
            // 定期发送保活消息以保持 SSH 会话活跃
            let keep_alive_interval = tokio::time::Duration::from_secs(60);
            loop {
                tokio::time::sleep(keep_alive_interval).await;
                let lock = session_arc.lock().await;
                // 设置 keepalive（这是一个设置方法，返回 void）
                if let Err(e) = std::io::Result::Ok(lock.set_keepalive(true, 30)) {
                    error!("设置保活消息失败: {}", e);
                    break;
                }
            }
        });
        
        info!("端口转发已建立: {}:{} -> 本地 SSH 服务器 {}:{}", 
              remote_host, remote_port, ssh_server.local_host, ssh_server.local_port);
        
        Ok(())
    }
}

// 此函数在新的实现中不再需要，保留为注释以防将来需要
/*
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
*/ 