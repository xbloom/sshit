# 第一阶段：构建环境
FROM rust:1.86-slim-bullseye AS builder

# 直接设置Debian镜像源，不做任何检查
RUN echo "deb http://mirrors.aliyun.com/debian/ bullseye main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list

# 安装构建依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends tree \
        pkg-config libssl-dev build-essential ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 设置RUSTFLAGS以最小化二进制大小
ENV RUSTFLAGS="-C opt-level=z -C codegen-units=1 "

# 设置CARGO_HOME环境变量
ENV CARGO_HOME=/usr/local/cargo

# 创建工作目录
WORKDIR /app

# 创建.cargo目录并配置国内镜像源
RUN mkdir -p .cargo
RUN echo '[source.crates-io]' > .cargo/config.toml && \
    echo 'replace-with = "rsproxy-sparse"' >> .cargo/config.toml && \
    echo '[source.rsproxy]' >> .cargo/config.toml && \
    echo 'registry = "https://rsproxy.cn/crates.io-index"' >> .cargo/config.toml && \
    echo '[source.rsproxy-sparse]' >> .cargo/config.toml && \
    echo 'registry = "sparse+https://rsproxy.cn/index/"' >> .cargo/config.toml && \
    echo '[registries.rsproxy]' >> .cargo/config.toml && \
    echo 'index = "https://rsproxy.cn/crates.io-index"' >> .cargo/config.toml && \
    echo '[net]' >> .cargo/config.toml && \
    echo 'git-fetch-with-cli = true' >> .cargo/config.toml


COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples/ssh_server_example.rs ./examples/

# 确保examples目录存在
RUN mkdir -p example

# 构建示例程序 - 使用--offline避免网络请求
RUN cargo build -v --release --example ssh_server_example 

# 剥离二进制，进一步减小尺寸
RUN strip /app/target/release/examples/ssh_server_example

# 第二阶段：运行时镜像
FROM debian:bullseye-slim as runtime

# 直接设置Debian镜像源，不做任何检查
RUN echo "deb http://mirrors.aliyun.com/debian/ bullseye main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list

# 使用非root用户
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# 安装最小运行时依赖，尝试不同的netcat包名
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates tzdata libssl1.1 netcat-traditional && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 复制二进制文件
COPY --from=builder /app/target/release/examples/ssh_server_example /usr/local/bin/

# 设置工作目录
WORKDIR /home/appuser
RUN chown -R appuser:appgroup /home/appuser
USER appuser

# 暴露SSH端口
EXPOSE 2222

# 健康检查（改用通用shell命令）
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD bash -c '</dev/tcp/localhost/2222' || exit 1

# 设置环境变量
ENV RUST_LOG=info

# 运行服务器
CMD ["ssh_server_example"] 