# SSH服务器示例 Docker容器

这个目录包含了构建最小化资源消耗的SSH服务器Docker容器的配置文件。

## 特点

- 使用多阶段构建，最小化容器大小
- 静态链接Rust二进制文件，减少依赖
- 基于Alpine Linux的轻量级运行时环境
- 非root用户运行，提高安全性
- 内置健康检查
- 最小化资源消耗（内存和CPU）
- 简单的构建和运行脚本

## 构建镜像

使用提供的构建脚本构建Docker镜像：

```bash
# 确保脚本有执行权限
chmod +x examples/build-docker.sh

# 执行构建脚本
./examples/build-docker.sh
```

或手动构建：

```bash
# 在项目根目录执行
docker build -f examples/Dockerfile -t ssh-proxy-server:latest .
```

## 运行容器

构建完成后，可以使用以下命令运行容器：

```bash
docker run -d -p 2222:2222 --name ssh-proxy ssh-proxy-server:latest
```

服务器将在容器内部的2222端口上运行，并映射到主机的2222端口。

## 连接到SSH服务器

使用以下命令连接到SSH服务器：

```bash
ssh admin@localhost -p 2222
```

默认凭据：
- 用户名：admin
- 密码：password

## 容器资源管理

运行时可以限制容器资源使用：

```bash
# 限制CPU和内存使用
docker run -d -p 2222:2222 --name ssh-proxy \
  --memory="64m" --memory-swap="128m" \
  --cpus="0.5" \
  ssh-proxy-server:latest
```

## 查看日志

```bash
docker logs ssh-proxy
```

## 停止和删除容器

```bash
docker stop ssh-proxy
docker rm ssh-proxy
``` 