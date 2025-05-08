use anyhow::Result;
use clap::Parser;
use log::info;
use rand::Rng;
use std::path::PathBuf;

mod key_manager;
mod ssh_client;
mod ssh_server;

use key_manager::KeyManager;
use ssh_client::SshClient;
use ssh_server::SshServer;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Remote SSH server host
    #[clap(short = 'H', long)]
    remote_host: String,

    /// Remote SSH server port
    #[clap(short = 'P', long, default_value = "22")]
    remote_port: u16,

    /// Local SSH server host to expose
    #[clap(short = 'L', long, default_value = "127.0.0.1")]
    local_host: String,

    /// Local SSH server port to expose
    #[clap(short = 'p', long, default_value = "22")]
    local_port: u16,

    /// Path to store generated key
    #[clap(short, long, default_value = "./ssh_proxy_key")]
    key_path: PathBuf,

    /// Remote user to connect as
    #[clap(short, long, default_value = "root")]
    user: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    // Generate one-time SSH key
    let key_manager = KeyManager::new(&args.key_path)?;
    let _keypair = key_manager.generate_keypair()?;
    
    // Display the public key for user to configure on remote server
    println!("\n=== ONE-TIME SSH PUBLIC KEY ===");
    println!("{}", key_manager.get_public_key_string()?);
    println!("Configure this key on your remote SSH server for user: {}", args.user);
    println!("Press Enter when ready to connect...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Connect to remote server
    let mut client = SshClient::new(
        args.remote_host.clone(), 
        args.remote_port,
        args.user, 
        args.key_path.clone()
    );
    
    info!("Connecting to remote SSH server...");
    client.connect().await?;
    
    // Choose a random port for the SSH server on the remote machine
    let remote_proxy_port = rand::thread_rng().gen_range(10000, 65535);
    info!("Starting SSH proxy on remote port: {}", remote_proxy_port);
    
    // Start SSH server
    let ssh_server = SshServer::new(
        args.local_host,
        args.local_port,
    );
    
    // Start port forwarding
    client.forward_remote_port(remote_proxy_port, ssh_server, args.remote_host.clone()).await?;
    
    println!("SSH proxy is running.");
    println!("Connect to your internal machine using:");
    println!("ssh -p {} user@{}", remote_proxy_port, args.remote_host);
    
    // Keep the connection alive
    tokio::signal::ctrl_c().await?;
    println!("Shutting down SSH proxy...");
    
    Ok(())
}
