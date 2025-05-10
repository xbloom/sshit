use ssh_proxy::{SshServer, SshServerConfig};
use simple_logger::SimpleLogger;
use log::LevelFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    SimpleLogger::new()
        .with_level(LevelFilter::Debug)
        .init()
        .unwrap();
    
    // 配置SSH服务器
    let config = SshServerConfig {
        listen_addr: "0.0.0.0".to_string(),
        listen_port: 2222,
        key_path: None, // 使用随机生成的密钥
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
    };
    
    // 创建并运行SSH服务器
    let mut server = SshServer::new(config);
    server.run().await?;
    
    Ok(())
} 