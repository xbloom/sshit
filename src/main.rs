use anyhow::Result;
use clap::Parser;
use rand::Rng;
use std::path::PathBuf;
use std::str::FromStr;

mod key_manager;
mod ssh_client;
mod ssh_server;
mod command_handler;
mod sftp_handler;

use key_manager::{KeyManager, SshKeyType};
use ssh_client::SshClient;
use ssh_server::{SshServer, SshServerConfig};
use ssh_proxy::setup_logging;

// Add a custom parser for SshKeyType from string
impl FromStr for SshKeyType {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(SshKeyType::Ed25519),
            "rsa" => Ok(SshKeyType::Rsa),
            _ => Err(anyhow::anyhow!("无效的SSH密钥类型: {}. 有效值: ed25519, rsa", s)),
        }
    }
}

#[derive(Parser, Debug)]
#[clap(name = "SSH Proxy", version = env!("CARGO_PKG_VERSION"), about = "SSH 代理工具")]
struct Args {
    /// 远程 SSH 服务器主机
    #[clap(short = 'H', long)]
    remote_host: String,

    /// 远程 SSH 服务器端口
    #[clap(short = 'P', long, default_value = "22")]
    remote_port: u16,

    /// 要暴露的本地 SSH 服务器主机
    #[clap(short = 'L', long, default_value = "127.0.0.1")]
    local_host: String,

    /// 要暴露的本地 SSH 服务器端口
    #[clap(short = 'p', long, default_value = "22")]
    local_port: u16,

    /// 存储或加载 SSH 密钥的路径
    #[clap(short, long, default_value = "./ssh_proxy_key")]
    key_path: PathBuf,

    /// 连接远程服务器的用户名
    #[clap(short, long, default_value = "root")]
    user: String,
    
    /// 要生成的 SSH 密钥类型 (ed25519 或 rsa)
    #[clap(short = 't', long, default_value = "ed25519")]
    key_type: SshKeyType,
    
    /// 使用现有密钥文件而不是生成新的
    /// 密钥文件应位于由 -k/--key_path 指定的路径
    #[clap(short = 'e', long)]
    use_existing_key: bool,

    /// SSH 服务器默认用户名
    #[clap(long, default_value = "admin")]
    server_username: String,

    /// SSH 服务器默认密码
    #[clap(long, default_value = "password")]
    server_password: String,
    
    /// SFTP 子系统的工作目录，默认为当前目录
    #[clap(long)]
    sftp_root_dir: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 使用新的日志初始化函数，设置默认日志级别为INFO
    setup_logging(tracing::Level::INFO, "SSH_PROXY");
    
    let args = Args::parse();

    // 使用span来跟踪关键操作
    let setup_span = tracing::info_span!("setup");
    let _setup_guard = setup_span.enter();
    
    // Generate or use existing SSH key
    tracing::debug!(
        key_path = %args.key_path.display(), 
        key_type = %args.key_type.as_str(),
        use_existing = args.use_existing_key,
        "设置SSH密钥"
    );
    
    let key_manager = KeyManager::new(&args.key_path, args.key_type, !args.use_existing_key)?;
    
    // If using existing key, check if it exists
    if args.use_existing_key && !key_manager.key_files_exist() {
        return Err(anyhow::anyhow!(
            "指定的密钥文件不存在于: {} 和 {}.pub。 \
            请使用不同的路径或移除 -e 标志以生成新的密钥。",
            args.key_path.display(), args.key_path.display()
        ));
    }
    
    key_manager.setup_keypair()?;
    
    // Display the public key for user to configure on remote server
    let pubkey = key_manager.get_public_key_string()?;
    
    println!("\n=== SSH 公钥 ===");
    println!("{}", pubkey);
    println!("请在远程服务器上为用户 {} 配置此密钥", args.user);
    
    if !args.use_existing_key {
        println!("这是一个一次性密钥，仅用于此会话。");
    }
    
    println!("配置完成后按 Enter 键继续连接...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // 连接操作使用新的span
    let connection_span = tracing::info_span!(
        "ssh_connection", 
        host = %args.remote_host, 
        port = args.remote_port, 
        user = %args.user
    );
    let _connection_guard = connection_span.enter();

    // Connect to remote server
    let mut client = SshClient::new(
        args.remote_host.clone(), 
        args.remote_port,
        args.user, 
        args.key_path.clone()
    );
    
    tracing::info!("正在连接远程SSH服务器...");
    client.connect().await?;
    
    // Choose a random port for the SSH server on the remote machine
    let remote_proxy_port = rand::thread_rng().gen_range(10000..65535);
    tracing::info!(port = remote_proxy_port, "在远程端口上启动SSH代理");
    
    // Start SSH server with default credentials
    let ssh_server = SshServer::new(
        SshServerConfig {
            listen_addr: args.local_host,
            listen_port: args.local_port,
            key_path: None, // 我们会生成一个随机密钥
            default_username: args.server_username.clone(),
            default_password: args.server_password.clone(),
            sftp_root_dir: args.sftp_root_dir.clone(),
        }
    );
    
    // Start port forwarding
    client.forward_remote_port(remote_proxy_port, ssh_server, args.remote_host.clone()).await?;
    
    println!("SSH 代理正在运行。");
    println!("使用以下命令连接到您的内部机器：");
    println!("ssh -p {} {}@{}", remote_proxy_port, args.server_username, args.remote_host);
    println!("默认密码: {}", args.server_password);
    
    tracing::info!(
        remote_port = remote_proxy_port,
        username = %args.server_username,
        "SSH代理成功启动"
    );
    
    // Keep the connection alive
    tokio::signal::ctrl_c().await?;
    tracing::info!("收到终止信号，正在关闭SSH代理...");
    println!("正在关闭 SSH 代理...");
    
    Ok(())
}
