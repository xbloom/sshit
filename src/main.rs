use anyhow::{Context, Result};
use clap::Parser;
use rand::Rng;
use tokio::io::AsyncBufReadExt;
use std::path::PathBuf;
use std::str::FromStr;

mod key_manager;
mod ssh_client;
mod ssh_server;
mod command_handler;
mod sftp_handler;
mod utils;

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
    remote_host: Option<String>,

    /// 远程 SSH 服务器端口
    #[clap(short = 'P', long, default_value = "22")]
    remote_port: u16,

    /// 要暴露的本地 SSH 服务器主机
    #[clap(short = 'L', long, default_value = "127.0.0.1")]
    local_host: String,

    /// 要暴露的本地 SSH 服务器端口
    #[clap(short = 'p', long, default_value = "2222")]
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
    #[clap(long, default_value = "nimda")]
    server_username: String,

    /// SSH 服务器密码（可选，如未指定则随机生成）
    #[clap(long)]
    server_password: Option<String>,
    
    /// SFTP 子系统的工作目录，默认为当前目录
    #[clap(long)]
    sftp_root_dir: Option<String>,
    
    /// 启用详细日志，用于调试连接问题
    #[clap(short = 'v', long)]
    verbose: bool,
}

/// 配置并启动日志系统
fn setup_app_logging(verbose: bool) {
    if verbose {
        // 设置详细日志，尤其是开启russh库的debug级别日志
        std::env::set_var("RUST_LOG", "russh=debug,russh_keys=debug");
        // 使用新的日志初始化函数，设置默认日志级别为DEBUG
        // 开启彩色日志
        std::env::set_var("COLORIZE_LOGS", "1");
        setup_logging(tracing::Level::DEBUG, "SSH_PROXY");
        
        tracing::info!("调试模式已开启，将显示详细的SSH连接日志");
    } else {
        // 使用新的日志初始化函数，设置默认日志级别为INFO
        // 确保不使用彩色日志
        std::env::remove_var("COLORIZE_LOGS");
        setup_logging(tracing::Level::INFO, "SSH_PROXY");
    }
}

/// 启动SSH服务器作为后台任务
async fn start_ssh_server(config: SshServerConfig) {
    let mut ssh_server = SshServer::new(config);
    tokio::spawn(async move {
        if let Err(e) = ssh_server.run().await {
            tracing::error!("SSH服务器运行错误: {}", e);
        }
    });
}

/// 准备SSH密钥并显示公钥信息
async fn prepare_ssh_key(args: &Args) -> Result<KeyManager> {
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
    
    let key_manager = KeyManager::new(&args.key_path, args.key_type, !args.use_existing_key)
        .context("创建密钥管理器失败")?;
    
    // If using existing key, check if it exists
    if args.use_existing_key && !key_manager.key_files_exist() {
        return Err(anyhow::anyhow!(
            "指定的密钥文件不存在于: {} 和 {}.pub。 \
            请使用不同的路径或移除 -e 标志以生成新的密钥。",
            args.key_path.display(), args.key_path.display()
        ));
    }
    
    key_manager.setup_keypair().context("设置SSH密钥对失败")?;
    
    // Display the public key for user to configure on remote server
    let pubkey = key_manager.get_public_key_string().context("获取公钥字符串失败")?;
    
    tracing::info!("");
    tracing::info!("    📜 ---【 SSH 公钥信息 】--- 📜");
    tracing::info!("    │");
    tracing::info!("    │  远程用户: '{}'", args.user);
    tracing::info!("    │  公钥内容:");
    tracing::info!("    │  ╭─────────────────────────────────────────────────╮");
    tracing::info!("    │  │ {} │", pubkey);
    tracing::info!("    │  ╰─────────────────────────────────────────────────╯");
    if !args.use_existing_key {
        tracing::info!("    │  提示: 这是一个一次性密钥，仅用于当前会话。");
    }
    tracing::info!("    │");
    tracing::info!("    📜 ------﹝请按上述信息配置远程服务器﹞------ 📜");

    Ok(key_manager)
}

/// 等待用户输入或超时
async fn wait_for_user_input() -> Result<()> {
    tracing::info!("");
    tracing::info!("    ⏳ >>> 请按【回车键】继续，或等待3秒后自动操作...");
    
    let mut line_buffer = String::new();
    let mut stdin_reader = tokio::io::BufReader::new(tokio::io::stdin());

    tokio::select! {
        // Branch 1: Wait for a 3-second timeout.
        _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
            tracing::info!("    ⏳ >>> 已超时，自动继续...");
        }
        // Branch 2: Wait for a line from stdin (or EOF).
        result = stdin_reader.read_line(&mut line_buffer) => {
            match result {
                Ok(_) => {
                    tracing::info!("    ⏳ >>> 已收到输入，继续操作...");
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("从stdin读取输入失败: {}", e));
                }
            }
        }
    }
    
    Ok(())
}

/// 连接到远程服务器并设置端口转发
async fn connect_and_forward(args: &Args, remote_host: &str) -> Result<()> {
    // 连接操作使用新的span
    let connection_span = tracing::info_span!(
        "ssh_connection", 
        host = %remote_host, 
        port = args.remote_port, 
        user = %args.user
    );
    let _connection_guard = connection_span.enter();

    // Connect to remote server using our SSH client
    let mut client = SshClient::new(
        remote_host.to_string(), 
        args.remote_port,
        args.user.clone(), 
        args.key_path.clone()
    );
    
    // Choose a random port for the SSH server on the remote machine
    let remote_proxy_port = rand::thread_rng().gen_range(10000..65535);
    tracing::info!(port = remote_proxy_port, "在远程端口上启动SSH代理");
    
    // 设置端口转发
    tracing::info!("正在连接远程SSH服务器并设置端口转发...");
    client.connect_and_forward(remote_proxy_port, args.local_host.clone(), args.local_port)
        .await
        .context("连接远程服务器或设置端口转发失败")?;
    
    tracing::info!("");
    tracing::info!("    🚀🌌~~~~~【 远程 SSH 代理已激活! 】~~~~~🌌🚀");
    tracing::info!("    │");
    tracing::info!("    │  代理目标: {}:{}", args.local_host, args.local_port);
    tracing::info!("    │  连接命令: ssh -p {} {}@{}", remote_proxy_port, args.server_username, remote_host);
    // 显示密码信息
    if let Some(password) = &args.server_password {
        tracing::info!("    │  认证信息:");
        tracing::info!("    │    🔑 用户: [ {} ]", args.server_username);
        tracing::info!("    │    🔒 密码: [ {} ] {}", password, 
            if args.server_password.as_ref().unwrap() == password { "(随机生成)" } else { "" });
    }
    tracing::info!("    │");
    tracing::info!("    🚀🌌~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~🌌🚀");

    tracing::info!(
        remote_port = remote_proxy_port,
        username = %args.server_username,
        "SSH代理成功启动" // This is a more structured log, not for direct user display
    );
    
    Ok(())
}

/// 显示本地SSH服务器信息
fn show_local_server_info(args: &Args) {
    tracing::info!("");
    tracing::info!("    🖥️💡~~~~~【 本地 SSH 服务器待命! 】~~~~~💡🖥️");
    tracing::info!("    │");
    tracing::info!("    │  监听地址: {}:{}", args.local_host, args.local_port);
    tracing::info!("    │  连接命令: ssh -p {} {}@{}", args.local_port, args.server_username, args.local_host);
    // 显示密码信息
    if let Some(password) = &args.server_password {
        tracing::info!("    │  认证信息:");
        tracing::info!("    │    🔑 用户: [ {} ]", args.server_username);
        tracing::info!("    │    🔒 密码: [ {} ] {}", password, 
            if args.server_password.as_ref().unwrap() == password { "(随机生成)" } else { "" });
    }
    tracing::info!("    │");
    tracing::info!("    🖥️💡~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~💡🖥️");

    tracing::info!(
        local_port = args.local_port,
        username = %args.server_username,
        "仅本地SSH服务器模式已启动" // Structured log
    );
}

/// 生成随机8位密码
fn generate_random_password(length: usize) -> String {
    // 使用字母数字和特殊字符生成随机密码
    let mut rng = rand::thread_rng();
    let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..chars.len());
            chars[idx] as char
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    // 解析命令行参数
    let mut args = Args::parse();
    
    // 设置日志系统
    setup_app_logging(args.verbose);

    // 输出 "Joan Stark 单鸭领航" 抬头
    tracing::info!("");
    tracing::info!("                 ,-.         ");
    tracing::info!("         ,      ( {{o\\        ");
    tracing::info!("         {{`\"=,___) (`~      ✨《《 SSH 隧道代理 v{} 》》✨", env!("CARGO_PKG_VERSION"));
    tracing::info!("          \\  ,_.-   )");
    tracing::info!("~^~^~^`- ~^ ~^ '~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~^~");
    
    // 确保有可用的密码 - 如果用户没有指定，则生成随机密码
    if args.server_password.is_none() {
        let random_password = generate_random_password(8);
        args.server_password = Some(random_password);
    }
    
    // 创建SSH服务器配置
    let config = SshServerConfig {
        listen_addr: args.local_host.clone(),
        listen_port: args.local_port,
        key_path: None, // 使用随机密钥
        default_username: args.server_username.clone(),
        default_password: args.server_password.clone().unwrap_or_default(),
        sftp_root_dir: args.sftp_root_dir.clone(),
    };
    
    // 启动SSH服务器
    start_ssh_server(config).await;

    // 只有当提供了远程主机参数时才执行远程连接和端口转发
    if let Some(remote_host) = &args.remote_host {
        // 准备SSH密钥
        prepare_ssh_key(&args).await?;
        
        // 等待用户输入或超时
        wait_for_user_input().await?;

        // 连接远程服务器并设置端口转发
        connect_and_forward(&args, remote_host).await?;
    } else {
        // 显示本地SSH服务器信息
        show_local_server_info(&args);
    }
    
    // 保持程序运行，直到收到Ctrl+C信号
    tokio::signal::ctrl_c().await.context("等待Ctrl+C信号失败")?;
    tracing::info!("");
    tracing::info!("    🛑⚡~~~~~【 SSH 代理正在关闭 】~~~~~⚡🛑");
    tracing::info!("    │         感谢使用! 再见!         │");
    tracing::info!("    🛑⚡~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~⚡🛑");
    
    Ok(())
}
