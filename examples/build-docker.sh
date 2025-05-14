#!/bin/sh
set -e

# 配置变量
IMAGE_NAME="ssh-proxy-server"
TAG="latest"

# 确保当前在项目根目录
cd "$(dirname "$0")/.."

echo "构建 $IMAGE_NAME:$TAG Docker 镜像..."

# 使用多CPU构建并优化镜像大小
docker build \
  --file examples/Dockerfile \
  --tag "$IMAGE_NAME:$TAG" \
  --build-arg RUST_VERSION=1.76 \
  --progress=plain \
  --compress \
  --force-rm \
  --no-cache \
  .

echo "构建完成！"
echo "你可以使用以下命令运行容器："
echo "docker run -d -p 2222:2222 --name ssh-proxy $IMAGE_NAME:$TAG"
echo "然后使用 'ssh admin@localhost -p 2222' 连接（密码: password）" 