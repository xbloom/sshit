use anyhow::Result;
use clap::Parser;
use log::info;
use rand::Rng;
use std::path::PathBuf;
use std::str::FromStr;

mod key_manager;
mod ssh_client;
mod ssh_server;

use key_manager::{KeyManager, SshKeyType};
use ssh_client::SshClient;
use ssh_server::SshServer;

// Add a custom parser for SshKeyType from string
impl FromStr for SshKeyType {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(SshKeyType::Ed25519),
            "rsa" => Ok(SshKeyType::Rsa),
            _ => Err(anyhow::anyhow!("Invalid key type: {}. Must be 'ed25519' or 'rsa'", s)),
        }
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about = "SSH 代理工具，用于通过外部服务器连接到内部 SSH 服务器", long_about = None)]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger with appropriate log level (info and above)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    // Generate or use existing SSH key
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
    println!("\n=== SSH 公钥 ===");
    println!("{}", key_manager.get_public_key_string()?);
    println!("请在远程服务器上为用户 {} 配置此密钥", args.user);
    
    if !args.use_existing_key {
        println!("这是一个一次性密钥，仅用于此会话。");
    }
    
    println!("配置完成后按 Enter 键继续连接...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Connect to remote server
    let mut client = SshClient::new(
        args.remote_host.clone(), 
        args.remote_port,
        args.user, 
        args.key_path.clone()
    );
    
    info!("正在连接远程 SSH 服务器...");
    client.connect().await?;
    
    // Choose a random port for the SSH server on the remote machine
    let remote_proxy_port = rand::thread_rng().gen_range(10000, 65535);
    info!("在远程端口 {} 上启动 SSH 代理", remote_proxy_port);
    
    // Start SSH server
    let ssh_server = SshServer::new(
        args.local_host,
        args.local_port,
    );
    
    // Start port forwarding
    client.forward_remote_port(remote_proxy_port, ssh_server, args.remote_host.clone()).await?;
    
    println!("SSH 代理正在运行。");
    println!("使用以下命令连接到您的内部机器：");
    println!("ssh -p {} user@{}", remote_proxy_port, args.remote_host);
    
    // Keep the connection alive
    tokio::signal::ctrl_c().await?;
    println!("正在关闭 SSH 代理...");
    
    Ok(())
}
