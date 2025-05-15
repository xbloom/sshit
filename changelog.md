# Changelog

## [Unreleased]

### Added
- 添加了对SSH动态端口转发（-D选项）的支持，现在可以使用此SSH代理作为SOCKS5代理
- 在启动时显示如何使用动态端口转发的说明
- 使用russh库实现SSH反向端口转发功能，改进了与远程服务器的连接稳定性和性能

### Fixed
- 修复了连接本地SSH服务器时"nodename nor servname provided, or not known"错误，通过确保在正确初始化ClientHandler后再建立端口转发

### Changed
- 将SSH客户端从ssh2库迁移到russh库，提高了系统的稳定性和兼容性
- 删除了不再需要的russh-keys依赖，简化了项目依赖关系

### Removed 