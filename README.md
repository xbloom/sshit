# SSH Proxy

一个Rust实现的SSH代理程序，用于将内网SSH服务暴露到公网。

## 功能

- 生成一次性SSH密钥对
- 通过反向连接将内网SSH服务暴露到公网
- 在远程服务器上自动开放随机端口
- 安全的SSH密钥认证

## 使用方法

### 编译

```bash
cargo build --release
```

编译后的可执行文件位于 `target/release/ssh-proxy`。

### 运行

```bash
./target/release/ssh-proxy --remote-host example.com --remote-port 22 --user username
```

### 参数说明

- `--remote-host` 或 `-r`: 远程SSH服务器地址
- `--remote-port` 或 `-p`: 远程SSH服务器端口（默认：22）
- `--local-host` 或 `-l`: 本地SSH服务器地址（默认：127.0.0.1）
- `--local-port` 或 `-o`: 本地SSH服务器端口（默认：22）
- `--key-path` 或 `-k`: 生成密钥的保存路径（默认：./ssh_proxy_key）
- `--user` 或 `-u`: 远程服务器上的用户名（默认：root）

### 使用流程

1. 运行程序，它会生成一个一次性SSH密钥对
2. 程序会显示公钥，将此公钥添加到远程服务器的`~/.ssh/authorized_keys`文件中
3. 添加完成后，按Enter键继续
4. 程序会连接远程服务器，并在远程服务器上开放一个随机端口
5. 使用SSH客户端连接到远程服务器的随机端口，即可访问内网SSH服务

## 安全注意事项

- 生成的密钥仅用于一次性连接，建议连接完成后删除
- 远程服务器应配置适当的防火墙规则
- 在生产环境中，建议实现更严格的密钥验证

## 依赖项

- tokio: 异步运行时
- russh: SSH库
- ed25519-dalek: 密钥生成
- clap: 命令行参数解析
- 其他依赖见Cargo.toml

## 许可证

MIT 