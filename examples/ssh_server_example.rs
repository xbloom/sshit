use ssh_proxy::{SshServer, SshServerConfig, setup_logging};
use tracing::{Level, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志，使用DEBUG级别
    setup_logging(Level::DEBUG, "SSH_PROXY");
    
    // 配置SSH服务器
    let config = SshServerConfig {
        listen_addr: "0.0.0.0".to_string(),
        listen_port: 2222,
        key_path: None, // 使用随机生成的密钥
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
        sftp_root_dir: None, // 添加sftp_root_dir字段
    };
    
    // 记录服务器配置信息
    info!(
        addr = %config.listen_addr,
        port = config.listen_port,
        username = %config.default_username,
        "启动SSH服务器示例"
    );
    
    // 创建并运行SSH服务器
    let mut server = SshServer::new(config);
    server.run().await?;
    
    Ok(())
} 