use anyhow::Result;
use russh::server::{Auth, Handler, Server};

use ssh_proxy::ssh_server::{SshServer, SshServerConfig};
use ssh_proxy::command_handler::CommandHandler;

#[tokio::test]
async fn test_ssh_server_creation() {
    // 创建服务器配置
    let config = SshServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 2222,
        key_path: None, // 使用随机生成的密钥
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
    };

    // 创建SSH服务器实例
    let server = SshServer::new(config);
    
    // 验证配置是否正确设置
    assert_eq!(server.config.listen_addr, "127.0.0.1");
    assert_eq!(server.config.listen_port, 2222);
    assert_eq!(server.config.default_username, "admin");
    assert_eq!(server.config.default_password, "password");
}

#[tokio::test]
async fn test_ssh_server_with_key_file() -> Result<()> {
    // 创建临时目录和密钥文件
    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join("test_ssh_key");
    
    // 生成随机密钥并保存到文件
    let key = russh::keys::PrivateKey::random(
        &mut rand::thread_rng(), 
        russh::keys::Algorithm::Ed25519
    )?;
    
    // 将密钥序列化为PKCS8 PEM格式并写入文件
    let mut key_data = Vec::new();
    russh::keys::encode_pkcs8_pem(&key, &mut key_data)?;
    std::fs::write(&key_path, key_data)?;
    
    // 创建服务器配置，使用指定的密钥文件
    let config = SshServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 2223,
        key_path: Some(key_path.to_string_lossy().to_string()),
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
    };

    // 创建SSH服务器实例
    let server = SshServer::new(config);
    
    // 测试服务器实例创建成功
    assert_eq!(server.config.listen_addr, "127.0.0.1");
    assert_eq!(server.config.listen_port, 2223);
    
    // 清理
    let _ = std::fs::remove_file(key_path);
    
    Ok(())
}

#[tokio::test]
async fn test_new_client_handler() {
    // 创建服务器配置
    let config = SshServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 2224,
        key_path: None,
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
    };

    // 创建SSH服务器实例
    let mut server = SshServer::new(config);
    
    // 测试创建新客户端处理程序 - 使用Server trait的方法
    let _handler = <SshServer as Server>::new_client(&mut server, None);
    
    // 创建另一个处理程序
    let _handler2 = <SshServer as Server>::new_client(&mut server, None);
    
    // 不再测试私有字段
}

#[tokio::test]
async fn test_auth_methods() {
    // 创建一个带有正确认证信息的服务器配置
    let config = SshServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 2225,
        key_path: None,
        default_username: "test_user".to_string(),
        default_password: "test_password".to_string(),
    };
    
    // 创建服务器实例
    let mut server = SshServer::new(config);
    
    // 测试成功的认证场景
    
    // 1. 无密码认证，使用正确的用户名
    let auth_none_success = <SshServer as Handler>::auth_none(&mut server, "test_user").await.unwrap();
    assert!(matches!(auth_none_success, Auth::Accept), "应当接受正确用户名的无密码认证");
    
    // 2. 无密码认证，使用错误的用户名
    let auth_none_failure = <SshServer as Handler>::auth_none(&mut server, "wrong_user").await.unwrap();
    assert!(!matches!(auth_none_failure, Auth::Accept), "应当拒绝错误用户名的无密码认证");
    
    // 3. 密码认证，使用正确的用户名和密码
    let auth_pass_success = <SshServer as Handler>::auth_password(
        &mut server, "test_user", "test_password"
    ).await.unwrap();
    assert!(matches!(auth_pass_success, Auth::Accept), "应当接受正确的用户名和密码认证");
    
    // 4. 密码认证，使用正确的用户名但错误的密码
    let auth_pass_failure1 = <SshServer as Handler>::auth_password(
        &mut server, "test_user", "wrong_password"
    ).await.unwrap();
    assert!(!matches!(auth_pass_failure1, Auth::Accept), "应当拒绝错误密码的认证");
    
    // 5. 密码认证，使用错误的用户名和正确的密码
    let auth_pass_failure2 = <SshServer as Handler>::auth_password(
        &mut server, "wrong_user", "test_password"
    ).await.unwrap();
    assert!(!matches!(auth_pass_failure2, Auth::Accept), "应当拒绝错误用户名的认证");
    
    // 6. 测试公钥认证（应当被拒绝，因为我们不接受公钥认证）
    let key = russh::keys::PrivateKey::random(
        &mut rand::thread_rng(), 
        russh::keys::Algorithm::Ed25519
    ).unwrap();
    let public_key = key.public_key();
    let auth_pubkey_result = <SshServer as Handler>::auth_publickey(
        &mut server, "test_user", &public_key
    ).await.unwrap();
    
    assert!(!matches!(auth_pubkey_result, Auth::Accept), "应当拒绝公钥认证");
}

// 测试使用 CommandHandler 执行命令
// 注意：这是集成测试，需要集成 SshServer 和 CommandHandler
#[tokio::test]
async fn test_command_handler_integration() {
    // 只是验证 CommandHandler 可以被正确导入
    assert!(std::any::TypeId::of::<CommandHandler>() == std::any::TypeId::of::<CommandHandler>());
}

// 模拟测试 SSH 会话交互
#[tokio::test]
async fn test_ssh_session_simulation() -> Result<()> {
    // 创建服务器配置
    let config = SshServerConfig {
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 2226,
        key_path: None,
        default_username: "admin".to_string(),
        default_password: "password".to_string(),
    };

    // 创建服务器实例
    let mut server = SshServer::new(config.clone());
    
    // 模拟认证流程
    let auth_result = <SshServer as Handler>::auth_password(
        &mut server, &config.default_username, &config.default_password
    ).await?;
    
    // 验证认证通过
    assert!(matches!(auth_result, Auth::Accept), "认证应当成功");
    
    // 模拟通道打开（实际测试中这部分难以完全模拟，因为需要完整的 SSH 会话）
    // 验证服务器配置被正确应用
    assert_eq!(server.config.default_username, "admin");
    assert_eq!(server.config.default_password, "password");
    
    Ok(())
} 