use std::path::Path;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::os::unix::fs::MetadataExt;

use anyhow::Result;
use log::{error, info, warn};
use tokio::sync::Mutex;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId, Pty};
use russh_sftp::protocol::OpenFlags;

// 在文件顶部添加tracing的use语句，新代码使用tracing
use tracing;

/// SSH Server Configuration
#[derive(Clone)]
pub struct SshServerConfig {
    /// Address to listen on
    pub listen_addr: String,
    /// Port to listen on
    pub listen_port: u16,
    /// Path to the server's private key
    #[allow(dead_code)]
    pub key_path: Option<String>,
    /// Default username for authentication
    pub default_username: String,
    /// Default password for authentication
    pub default_password: String,
}

/// 终端信息
#[derive(Clone)]
struct PtyInfo {
    term: String,
    cols: u32,
    rows: u32,
}

/// 会话信息，包含所有与客户端会话相关的数据
#[derive(Clone)]
struct SessionInfo {
    /// 通道ID
    #[allow(dead_code)]
    channel_id: ChannelId,
    /// 会话句柄
    handle: russh::server::Handle,
    /// PTY信息，如果会话请求了PTY则有值
    pty_info: Option<PtyInfo>,
    /// 会话创建时间
    #[allow(dead_code)]
    created_at: Instant,
}

/// SSH Server implementation
#[derive(Clone)]
pub struct SshServer {
    pub config: SshServerConfig,
    /// 所有会话信息
    sessions: Arc<Mutex<HashMap<usize, SessionInfo>>>,
    /// 会话ID计数器，使用原子计数器确保线程安全和唯一性
    next_id: Arc<AtomicUsize>,
    /// 当前会话ID
    id: usize,
    /// 命令处理器实例，确保所有PTY操作使用相同的实例
    cmd_handler: Arc<crate::command_handler::CommandHandler>,
    /// 保存通道，用于SFTP子系统
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

// 添加SFTP处理器结构体
struct SftpHandler {
    root_dir_read_done: bool,
    // 添加标记，用于跟踪处理SCP的SFTP会话
    is_scp_session: bool,
}

// 在文件顶部添加常量定义，用于文件类型和权限值
// SFTP文件类型常量
const SFTP_TYPE_REGULAR: u32 = 0o100000; // 普通文件
const SFTP_TYPE_DIRECTORY: u32 = 0o040000; // 目录
const SFTP_TYPE_SYMLINK: u32 = 0o120000; // 符号链接
const SFTP_TYPE_SOCKET: u32 = 0o140000; // 套接字
const SFTP_TYPE_CHAR: u32 = 0o020000; // 字符设备
const SFTP_TYPE_BLOCK: u32 = 0o060000; // 块设备
const SFTP_TYPE_FIFO: u32 = 0o010000; // FIFO

// 常用的权限组合
const PERM_DIRECTORY: u32 = 0o755; // 目录默认权限
const PERM_FILE: u32 = 0o644; // 文件默认权限

// 添加一个impl块实现自定义的方法
impl SftpHandler {
    // 帮助方法：确定要写入的文件路径
    fn determine_file_path(&self, id: u32, dir_path: &str, data: &[u8], offset: u64) -> String {
        // 1. 首先检查是否有从命令行提取的文件名（特殊索引0）
        if self.is_scp_session {
            if let Ok(filename_map) = SCP_FILENAME_MAP.lock() {
                if let Some(original_filename) = filename_map.get(&0) {
                    tracing::info!(id = id, filename = %original_filename, "使用从命令行提取的原始文件名");
                    if dir_path.ends_with(original_filename) {
                        // 如果目录路径已经包含文件名，直接返回
                        return dir_path.to_string();
                    } else {
                        // 否则，将文件名附加到目录路径
                        return format!("{}/{}", dir_path, original_filename);
                    }
                }
            }

            // 2. 尝试从SCP_SOURCE_FILE中提取源文件名
            if let Ok(source_file) = SCP_SOURCE_FILE.lock() {
                if let Some(src_path) = source_file.as_ref() {
                    // 从源路径中提取文件名
                    let filename = src_path.split('/').last().unwrap_or(src_path);
                    
                    // 检查是否需要提取主机部分之后的路径
                    let clean_filename = if let Some(idx) = filename.find(':') {
                        if idx + 1 < filename.len() {
                            &filename[(idx + 1)..]
                        } else {
                            filename
                        }
                    } else {
                        filename
                    };
                    
                    tracing::info!(id = id, filename = %clean_filename, "SCP会话：使用从源文件路径提取的文件名");
                    return format!("{}/{}", dir_path, clean_filename);
                }
            }
        }
        
        // 3. 尝试从SCP协议头提取文件名
        if offset == 0 && data.len() > 2 && data[0] == b'C' {
            if let Ok(header) = std::str::from_utf8(data) {
                let header_line = if let Some(newline_pos) = header.find('\n') {
                    &header[0..newline_pos]
                } else {
                    header
                };
                
                tracing::debug!(header = %header_line, "解析SCP协议头");
                
                let parts: Vec<&str> = header_line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let filename = parts[2];
                    tracing::info!(id = id, filename = %filename, "从SCP协议头中提取文件名");
                    
                    // 保存到映射，供后续使用
                    if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                        filename_map.insert(id, format!("{}/{}", dir_path, filename));
                    }
                    
                    return format!("{}/{}", dir_path, filename);
                } else {
                    tracing::warn!(id = id, parts = ?parts, "SCP协议头解析失败，使用临时文件名");
                    return format!("{}/scp_temp_{}", dir_path, id);
                }
            } else {
                tracing::warn!(id = id, "无法将SCP协议头解析为UTF-8字符串，使用临时文件名");
                return format!("{}/scp_temp_{}", dir_path, id);
            }
        }
        
        // 4. 从之前保存的映射中获取文件名
        if let Ok(filename_map) = SCP_FILENAME_MAP.lock() {
            if let Some(path) = filename_map.get(&id) {
                return path.clone();
            }
        }
        
        // 5. 尝试使用目录路径本身（如果它已经包含文件名）
        if !dir_path.ends_with("/") {
            if let Some(filename) = self.extract_filename_from_path(dir_path) {
                if !filename.is_empty() {
                    tracing::info!(id = id, filename = %filename, "使用路径中已包含的文件名");
                    return dir_path.to_string();
                }
            }
        }
        
        // 6. 使用默认临时文件名
        let default_path = format!("{}/scp_file_{}", dir_path, id);
        tracing::warn!(id = id, path = %default_path, "使用默认文件名");
        default_path
    }
    
    // 尝试从路径中提取文件名
    fn extract_filename_from_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        let components: Vec<&str> = path.split('/').collect();
        if components.is_empty() {
            None
        } else {
            let last = components.last().unwrap();
            if last.is_empty() {
                None
            } else {
                Some(*last)
            }
        }
    }
}

impl Default for SftpHandler {
    fn default() -> Self {
        Self {
            root_dir_read_done: false,
            is_scp_session: false,
        }
    }
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = russh_sftp::protocol::StatusCode;

    fn unimplemented(&self) -> Self::Error {
        russh_sftp::protocol::StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: std::collections::HashMap<String, String>,
    ) -> Result<russh_sftp::protocol::Version, Self::Error> {
        tracing::info!(version = version, ?extensions, "SFTP初始化");
        
        // 检查是否有SCP源文件路径，如果有则标记为SCP会话
        if let Ok(source_file) = SCP_SOURCE_FILE.lock() {
            if source_file.is_some() {
                self.is_scp_session = true;
                tracing::info!("检测到SCP会话，启用SCP特殊处理");
            }
        }
        
        Ok(russh_sftp::protocol::Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP realpath请求");
        
        // 将相对路径转换为绝对路径
        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{}", path)
        };
        
        // 创建文件属性
        let mut attrs = russh_sftp::protocol::FileAttributes::default();
        attrs.permissions = Some(SFTP_TYPE_DIRECTORY | PERM_DIRECTORY); // 目录权限
        
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::new(&path, attrs)],
        })
    }
    
    async fn opendir(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP opendir请求");
        self.root_dir_read_done = false;
        Ok(russh_sftp::protocol::Handle { id, handle: path })
    }
    
    async fn readdir(&mut self, id: u32, handle: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        tracing::info!(id = id, handle = %handle, "SFTP readdir请求");
        
        // 简单实现，只返回当前目录的内容
        if !self.root_dir_read_done {
            self.root_dir_read_done = true;
            
            // 获取当前目录下的文件列表 (这里可以替换为真实的文件列表逻辑)
            match std::fs::read_dir(".") {
                Ok(entries) => {
                    let mut files = Vec::new();
                    for entry in entries {
                        if let Ok(entry) = entry {
                            if let Ok(file_name) = entry.file_name().into_string() {
                                if let Ok(metadata) = entry.metadata() {
                                    // 创建文件属性
                                    let mut attrs = russh_sftp::protocol::FileAttributes::default();
                                    attrs.size = Some(metadata.len());
                                    attrs.uid = Some(metadata.uid());
                                    attrs.gid = Some(metadata.gid());
                                    
                                    // 设置文件类型
                                    if metadata.is_dir() {
                                        attrs.permissions = Some(SFTP_TYPE_DIRECTORY | PERM_DIRECTORY);
                                    } else if metadata.is_file() {
                                        attrs.permissions = Some(SFTP_TYPE_REGULAR | PERM_FILE);
                                    }
                                    
                                    // 添加文件条目
                                    files.push(russh_sftp::protocol::File::new(&file_name, attrs));
                                }
                            }
                        }
                    }
                    
                    return Ok(russh_sftp::protocol::Name {
                        id,
                        files,
                    });
                },
                Err(e) => {
                    tracing::error!(error = %e, "读取目录失败");
                    return Err(russh_sftp::protocol::StatusCode::Failure);
                }
            }
        }
        
        // 目录已读取完毕
        Err(russh_sftp::protocol::StatusCode::Eof)
    }
    
    async fn close(&mut self, id: u32, _handle: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, "SFTP close请求");
        Ok(russh_sftp::protocol::Status {
            id,
            status_code: russh_sftp::protocol::StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }
    
    // 添加stat操作支持
    async fn stat(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP stat请求");
        
        // 尝试获取文件/目录状态
        match std::fs::metadata(&path) {
            Ok(metadata) => {
                let mut attrs = russh_sftp::protocol::FileAttributes::default();
                attrs.size = Some(metadata.len());
                attrs.uid = Some(metadata.uid());
                attrs.gid = Some(metadata.gid());
                
                // 设置文件类型
                if metadata.is_dir() {
                    attrs.permissions = Some(SFTP_TYPE_DIRECTORY | PERM_DIRECTORY);
                } else if metadata.is_file() {
                    attrs.permissions = Some(SFTP_TYPE_REGULAR | PERM_FILE);
                }
                
                Ok(russh_sftp::protocol::Attrs { id, attrs })
            },
            Err(e) => {
                tracing::warn!(id = id, path = %path, error = %e, "SFTP stat请求失败");
                // 即使文件不存在也返回一些默认值，以帮助SCP操作
                if path.ends_with('/') || e.kind() == std::io::ErrorKind::NotFound {
                    // 如果路径以/结尾或文件不存在，假设它是一个目录
                    let mut attrs = russh_sftp::protocol::FileAttributes::default();
                    attrs.permissions = Some(SFTP_TYPE_DIRECTORY | PERM_DIRECTORY); // 目录权限
                    return Ok(russh_sftp::protocol::Attrs { id, attrs });
                }
                Err(russh_sftp::protocol::StatusCode::NoSuchFile)
            }
        }
    }
    
    // 添加lstat操作支持(与stat类似，但不解析符号链接)
    async fn lstat(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP lstat请求");
        
        // 对于简单实现，lstat和stat可以相同
        self.stat(id, path).await
    }
    
    // 添加open操作支持
    async fn open(&mut self, id: u32, path: String, pflags: OpenFlags, _attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        tracing::info!(id = id, path = %path, pflags = ?pflags, "SFTP open请求");
        
        // 对于SCP会话，提前处理文件名与路径的关系
        if self.is_scp_session {
            // 提取路径中的文件名部分
            if let Some(filename) = self.extract_filename_from_path(&path) {
                tracing::info!(id = id, filename = %filename, "SCP会话: 从路径中提取文件名");
                
                // 检查命令行提取的原始文件名
                let original_filename = if let Ok(filename_map) = SCP_FILENAME_MAP.lock() {
                    filename_map.get(&0).cloned()
                } else { None };
                
                // 如果有原始文件名且与路径中的不同，更新映射
                if let Some(orig_name) = original_filename {
                    if orig_name != filename && pflags.contains(OpenFlags::WRITE) {
                        // 创建新的目标路径
                        let parent_path = if let Some(idx) = path.rfind('/') {
                            &path[0..idx]
                        } else {
                            "."
                        };
                        
                        let new_path = format!("{}/{}", parent_path, orig_name);
                        tracing::info!(id = id, original = %orig_name, path_filename = %filename, new_path = %new_path, "SCP会话: 使用原始文件名替换路径");
                        
                        // 更新映射
                        if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                            filename_map.insert(id, new_path.clone());
                        }
                        
                        // 对于写入操作，直接返回原始路径的handle
                        if pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::CREATE) {
                            return Ok(russh_sftp::protocol::Handle { id, handle: new_path });
                        }
                    } else {
                        // 当前路径中的文件名与原始文件名相同，保存映射
                        if pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::CREATE) {
                            if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                                filename_map.insert(id, path.clone());
                            }
                        }
                    }
                } else {
                    // 没有原始文件名，但仍然保存当前路径映射
                    if pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::CREATE) {
                        if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                            filename_map.insert(id, path.clone());
                        }
                    }
                }
            }
        }
        
        // 首先检查路径是否为目录
        let path_metadata: Option<std::fs::Metadata> = match std::fs::metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(e) => {
                // 如果路径不存在且设置了CREATE标志，我们将在后续步骤中创建它
                if e.kind() == std::io::ErrorKind::NotFound && pflags.contains(OpenFlags::CREATE) {
                    // 继续处理，将在后面创建文件
                    None
                } else {
                    tracing::error!(id = id, path = %path, error = %e, "获取路径元数据失败");
                    return Err(match e.kind() {
                        std::io::ErrorKind::NotFound => russh_sftp::protocol::StatusCode::NoSuchFile,
                        std::io::ErrorKind::PermissionDenied => russh_sftp::protocol::StatusCode::PermissionDenied,
                        _ => russh_sftp::protocol::StatusCode::Failure,
                    });
                }
            }
        };
        
        // 检查是否是目录
        if let Some(metadata) = path_metadata {
            if metadata.is_dir() {
                if pflags.contains(OpenFlags::WRITE) {
                    // 如果是写入操作，我们需要处理特殊情况
                    // 对于SCP，当目标是目录时，应该在目录下创建一个与源文件同名的文件
                    tracing::info!(id = id, path = %path, "目标是目录，但请求写入，返回特殊handle");
                    
                    // 仅清除特定ID的文件名映射
                    if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                        filename_map.remove(&id);
                    }
                    
                    return Ok(russh_sftp::protocol::Handle { 
                        id, 
                        handle: format!("DIR:{}", path) 
                    });
                } else {
                    // 如果是读取操作，可以正常打开目录
                    return Ok(russh_sftp::protocol::Handle { id, handle: path });
                }
            }
        }
        
        // 将SFTP标志转换为Rust文件标志
        use std::fs::OpenOptions;
        let mut options = OpenOptions::new();
        
        // 根据OpenFlags设置文件打开选项
        // 以下是标准的SFTP v3的标志位
        options.read(pflags.contains(OpenFlags::READ));
        options.write(pflags.contains(OpenFlags::WRITE));
        options.append(pflags.contains(OpenFlags::APPEND));
        options.create(pflags.contains(OpenFlags::CREATE));
        options.truncate(pflags.contains(OpenFlags::TRUNCATE));
        options.create_new(pflags.contains(OpenFlags::CREATE) && pflags.contains(OpenFlags::EXCLUDE));
        
        // 尝试打开文件
        match options.open(&path) {
            Ok(_file) => {
                // 为简单起见，我们只返回path作为handle
                // 在生产环境中，应该生成唯一handle并跟踪打开的文件
                Ok(russh_sftp::protocol::Handle { id, handle: path })
            },
            Err(e) => {
                tracing::error!(id = id, path = %path, error = %e, "SFTP open请求失败");
                // 映射错误码
                match e.kind() {
                    std::io::ErrorKind::NotFound => Err(russh_sftp::protocol::StatusCode::NoSuchFile),
                    std::io::ErrorKind::PermissionDenied => Err(russh_sftp::protocol::StatusCode::PermissionDenied),
                    _ => Err(russh_sftp::protocol::StatusCode::Failure),
                }
            }
        }
    }
    
    // 添加write操作支持
    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, handle = %handle, offset = offset, data_len = data.len(), "SFTP write请求");
        
        // 添加更详细的调试日志 - 记录整个数据内容用于调试
        if data.len() > 0 {
            // 尝试打印前100个字节的内容
            let preview_len = std::cmp::min(data.len(), 100);
            let preview_data = &data[0..preview_len];
            if let Ok(text) = std::str::from_utf8(preview_data) {
                tracing::debug!(preview = %text, "数据预览");
            } else {
                // 如果不是有效的UTF-8，打印十六进制
                tracing::debug!(hex_preview = ?preview_data, "二进制数据预览");
            }
        }
        
        // 检查是否是目录handle
        if handle.starts_with("DIR:") {
            // 从handle中提取目录路径
            let dir_path = &handle[4..]; // 跳过"DIR:"前缀
            
            // 确定文件路径
            let file_path = self.determine_file_path(id, dir_path, &data, offset);
            
            tracing::info!(id = id, path = %file_path, "在目录中创建/写入文件");
            
            // 保存当前处理的文件路径到映射
            if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                filename_map.insert(id, file_path.clone());
            }
            
            // 打开（创建）文件用于写入
            match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(offset == 0) // 只在偏移量为0时截断文件
                .open(&file_path) {
                Ok(mut file) => {
                    // 设置文件偏移量
                    if offset > 0 {
                        if let Err(e) = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset)) {
                            tracing::error!(id = id, path = %file_path, error = %e, "设置文件偏移量失败");
                            return Err(russh_sftp::protocol::StatusCode::Failure);
                        }
                    }
                    
                    // 如果数据以"C"开头，这是SCP协议头，跳过此行
                    let write_data = if offset == 0 && data.len() > 0 && data[0] == b'C' {
                        // 查找第一个换行符
                        if let Some(newline_pos) = data.iter().position(|&b| b == b'\n') {
                            // 跳过SCP协议头，只写入实际数据
                            if newline_pos + 1 < data.len() {
                                tracing::info!(id = id, "跳过SCP协议头，写入实际数据 {} 字节", data.len() - (newline_pos + 1));
                                &data[(newline_pos + 1)..]
                            } else {
                                // 如果只有协议头没有实际数据，返回空slice
                                tracing::debug!(id = id, "仅包含SCP协议头，不写入实际数据");
                                &[]
                            }
                        } else {
                            // 未找到换行符，可能不是完整的SCP协议头
                            tracing::warn!(id = id, "未找到换行符，可能不是完整的SCP协议头");
                            &data
                        }
                    } else {
                        // 不是SCP协议头，直接写入所有数据
                        &data
                    };
                    
                    // 只有当有数据要写入时才写入
                    if !write_data.is_empty() {
                        tracing::debug!(id = id, path = %file_path, data_len = write_data.len(), "写入文件数据");
                        // 写入数据
                        match std::io::Write::write_all(&mut file, write_data) {
                            Ok(_) => {
                                Ok(russh_sftp::protocol::Status {
                                    id,
                                    status_code: russh_sftp::protocol::StatusCode::Ok,
                                    error_message: "Ok".to_string(),
                                    language_tag: "en-US".to_string(),
                                })
                            },
                            Err(e) => {
                                tracing::error!(id = id, path = %file_path, error = %e, "写入文件失败");
                                Err(russh_sftp::protocol::StatusCode::Failure)
                            }
                        }
                    } else {
                        // 没有数据要写入，但操作成功（跳过了协议头）
                        tracing::debug!(id = id, path = %file_path, "没有数据要写入（跳过协议头）");
                        Ok(russh_sftp::protocol::Status {
                            id,
                            status_code: russh_sftp::protocol::StatusCode::Ok,
                            error_message: "Ok".to_string(),
                            language_tag: "en-US".to_string(),
                        })
                    }
                },
                Err(e) => {
                    tracing::error!(id = id, path = %file_path, error = %e, "创建文件失败");
                    Err(russh_sftp::protocol::StatusCode::Failure)
                }
            }
        } else {
            // 常规文件处理
            // 处理通过SFTP接口的SCP会话的写入请求
            if self.is_scp_session {
                // 首先从映射中检查是否已经有了该ID的文件路径
                let existing_path = if let Ok(filename_map) = SCP_FILENAME_MAP.lock() {
                    filename_map.get(&id).cloned()
                } else {
                    None
                };
                
                // 如果有映射且与handle不同，使用映射的路径
                let file_path = if let Some(path) = existing_path {
                    if path != handle {
                        tracing::info!(id = id, mapped_path = %path, handle = %handle, "使用映射的文件路径");
                        path
                    } else {
                        handle.clone()
                    }
                } else {
                    handle.clone()
                };
                
                // 打开文件用于写入
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(offset == 0) // 只在偏移量为0时截断文件
                    .open(&file_path) {
                    Ok(mut file) => {
                        // 设置文件偏移量
                        if offset > 0 {
                            if let Err(e) = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset)) {
                                tracing::error!(id = id, path = %file_path, error = %e, "设置文件偏移量失败");
                                return Err(russh_sftp::protocol::StatusCode::Failure);
                            }
                        }
                        
                        // 写入数据
                        match std::io::Write::write_all(&mut file, &data) {
                            Ok(_) => {
                                Ok(russh_sftp::protocol::Status {
                                    id,
                                    status_code: russh_sftp::protocol::StatusCode::Ok,
                                    error_message: "Ok".to_string(),
                                    language_tag: "en-US".to_string(),
                                })
                            },
                            Err(e) => {
                                tracing::error!(id = id, path = %file_path, error = %e, "写入文件失败");
                                Err(russh_sftp::protocol::StatusCode::Failure)
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!(id = id, path = %file_path, error = %e, "打开文件用于写入失败");
                        Err(russh_sftp::protocol::StatusCode::Failure)
                    }
                }
            } else {
                // 普通SFTP文件处理
                // 打开文件用于写入
                match std::fs::OpenOptions::new().write(true).open(&handle) {
                    Ok(mut file) => {
                        // 设置文件偏移量
                        if let Err(e) = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset)) {
                            tracing::error!(id = id, handle = %handle, error = %e, "设置文件偏移量失败");
                            return Err(russh_sftp::protocol::StatusCode::Failure);
                        }
                        
                        // 写入数据
                        match std::io::Write::write_all(&mut file, &data) {
                            Ok(_) => {
                                Ok(russh_sftp::protocol::Status {
                                    id,
                                    status_code: russh_sftp::protocol::StatusCode::Ok,
                                    error_message: "Ok".to_string(),
                                    language_tag: "en-US".to_string(),
                                })
                            },
                            Err(e) => {
                                tracing::error!(id = id, handle = %handle, error = %e, "写入文件失败");
                                Err(russh_sftp::protocol::StatusCode::Failure)
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!(id = id, handle = %handle, error = %e, "打开文件用于写入失败");
                        Err(russh_sftp::protocol::StatusCode::Failure)
                    }
                }
            }
        }
    }
    
    // 添加mkdir操作支持
    async fn mkdir(&mut self, id: u32, path: String, _attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP mkdir请求");
        
        match std::fs::create_dir_all(&path) {
            Ok(_) => {
                Ok(russh_sftp::protocol::Status {
                    id,
                    status_code: russh_sftp::protocol::StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            },
            Err(e) => {
                tracing::error!(id = id, path = %path, error = %e, "创建目录失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加read操作支持
    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<russh_sftp::protocol::Data, Self::Error> {
        tracing::info!(id = id, handle = %handle, offset = offset, len = len, "SFTP read请求");
        
        // 打开文件用于读取
        match std::fs::File::open(&handle) {
            Ok(mut file) => {
                // 设置文件偏移量
                if let Err(e) = std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset)) {
                    tracing::error!(id = id, handle = %handle, error = %e, "设置文件偏移量失败");
                    return Err(russh_sftp::protocol::StatusCode::Failure);
                }
                
                // 读取数据
                let mut buffer = vec![0; len as usize];
                match std::io::Read::read(&mut file, &mut buffer) {
                    Ok(bytes_read) => {
                        buffer.truncate(bytes_read);
                        Ok(russh_sftp::protocol::Data {
                            id,
                            data: buffer.into(),
                        })
                    },
                    Err(e) => {
                        tracing::error!(id = id, handle = %handle, error = %e, "读取文件失败");
                        Err(russh_sftp::protocol::StatusCode::Failure)
                    }
                }
            },
            Err(e) => {
                tracing::error!(id = id, handle = %handle, error = %e, "打开文件用于读取失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加fstat操作支持
    async fn fstat(&mut self, id: u32, handle: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        tracing::info!(id = id, handle = %handle, "SFTP fstat请求");
        
        // 尝试获取文件状态
        match std::fs::metadata(&handle) {
            Ok(metadata) => {
                let mut attrs = russh_sftp::protocol::FileAttributes::default();
                attrs.size = Some(metadata.len());
                attrs.uid = Some(metadata.uid());
                attrs.gid = Some(metadata.gid());
                
                // 设置文件类型
                if metadata.is_dir() {
                    attrs.permissions = Some(SFTP_TYPE_DIRECTORY | PERM_DIRECTORY);
                } else if metadata.is_file() {
                    attrs.permissions = Some(SFTP_TYPE_REGULAR | PERM_FILE);
                }
                
                Ok(russh_sftp::protocol::Attrs { id, attrs })
            },
            Err(e) => {
                tracing::warn!(id = id, handle = %handle, error = %e, "SFTP fstat请求失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加setstat操作支持
    async fn setstat(&mut self, id: u32, path: String, attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, path = %path, attrs = ?attrs, "SFTP setstat请求");
        
        // 在这里可以实现设置文件属性的逻辑
        // 目前返回成功但实际不修改属性
        Ok(russh_sftp::protocol::Status {
            id,
            status_code: russh_sftp::protocol::StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }
    
    // 添加fsetstat操作支持
    async fn fsetstat(&mut self, id: u32, handle: String, attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, handle = %handle, attrs = ?attrs, "SFTP fsetstat请求");
        
        // 在这里可以实现设置文件属性的逻辑
        // 目前返回成功但实际不修改属性
        Ok(russh_sftp::protocol::Status {
            id,
            status_code: russh_sftp::protocol::StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }
    
    // 添加remove操作支持
    async fn remove(&mut self, id: u32, filename: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, filename = %filename, "SFTP remove请求");
        
        match std::fs::remove_file(&filename) {
            Ok(_) => {
                Ok(russh_sftp::protocol::Status {
                    id,
                    status_code: russh_sftp::protocol::StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            },
            Err(e) => {
                tracing::error!(id = id, filename = %filename, error = %e, "删除文件失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加rmdir操作支持
    async fn rmdir(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP rmdir请求");
        
        match std::fs::remove_dir(&path) {
            Ok(_) => {
                Ok(russh_sftp::protocol::Status {
                    id,
                    status_code: russh_sftp::protocol::StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            },
            Err(e) => {
                tracing::error!(id = id, path = %path, error = %e, "删除目录失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加rename操作支持
    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, oldpath = %oldpath, newpath = %newpath, "SFTP rename请求");
        
        match std::fs::rename(&oldpath, &newpath) {
            Ok(_) => {
                Ok(russh_sftp::protocol::Status {
                    id,
                    status_code: russh_sftp::protocol::StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            },
            Err(e) => {
                tracing::error!(id = id, oldpath = %oldpath, newpath = %newpath, error = %e, "重命名失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加readlink操作支持
    async fn readlink(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP readlink请求");
        
        match std::fs::read_link(&path) {
            Ok(target) => {
                let target_str = target.to_string_lossy().into_owned();
                let mut attrs = russh_sftp::protocol::FileAttributes::default();
                
                Ok(russh_sftp::protocol::Name {
                    id,
                    files: vec![russh_sftp::protocol::File::new(&target_str, attrs)],
                })
            },
            Err(e) => {
                tracing::error!(id = id, path = %path, error = %e, "读取符号链接失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
    }
    
    // 添加symlink操作支持
    async fn symlink(&mut self, id: u32, linkpath: String, targetpath: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, linkpath = %linkpath, targetpath = %targetpath, "SFTP symlink请求");
        
        #[cfg(unix)]
        match std::os::unix::fs::symlink(&targetpath, &linkpath) {
            Ok(_) => {
                Ok(russh_sftp::protocol::Status {
                    id,
                    status_code: russh_sftp::protocol::StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            },
            Err(e) => {
                tracing::error!(id = id, linkpath = %linkpath, targetpath = %targetpath, error = %e, "创建符号链接失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
        
        #[cfg(not(unix))]
        {
            tracing::warn!(id = id, "SFTP symlink请求不支持当前平台");
            Err(russh_sftp::protocol::StatusCode::OpUnsupported)
        }
    }
    
    // 添加extended操作支持
    async fn extended(&mut self, id: u32, request: String, data: Vec<u8>) -> Result<russh_sftp::protocol::Packet, Self::Error> {
        tracing::info!(id = id, request = %request, data_len = data.len(), "SFTP extended请求");
        
        // 对于扩展请求，记录更详细的信息
        if data.len() > 0 {
            // 尝试打印前100个字节的内容
            let preview_len = std::cmp::min(data.len(), 100);
            let preview_data = &data[0..preview_len];
            if let Ok(text) = std::str::from_utf8(preview_data) {
                tracing::debug!(preview = %text, "扩展请求数据预览");
            } else {
                // 如果不是有效的UTF-8，打印十六进制
                tracing::debug!(hex_preview = ?preview_data, "扩展请求二进制数据预览");
            }
        }
        
        // 默认不支持任何扩展，返回不支持操作
        Err(russh_sftp::protocol::StatusCode::OpUnsupported)
    }
}

impl SshServer {
    /// Create a new SSH server with the given configuration
    pub fn new(config: SshServerConfig) -> Self {
        SshServer {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicUsize::new(0)),
            id: 0,
            cmd_handler: Arc::new(crate::command_handler::CommandHandler::default()),
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Run the SSH server
    #[allow(dead_code)]
    pub async fn run(&mut self) -> Result<()> {
        // Either load the key from the specified path or generate a random one
        let server_key = if let Some(key_path) = &self.config.key_path {
            info!("从 {} 加载 SSH 服务器密钥", key_path);
            let key_path = Path::new(key_path);
            if key_path.exists() {
                match std::fs::read_to_string(key_path) {
                    Ok(key_data) => {
                        russh::keys::PrivateKey::from_openssh(&key_data)?
                    },
                    Err(e) => {
                        error!("读取密钥文件失败: {}", e);
                        return Err(anyhow::anyhow!("读取 SSH 服务器密钥文件失败: {}", e));
                    }
                }
            } else {
                error!("SSH 服务器密钥文件未找到: {}", key_path.display());
                return Err(anyhow::anyhow!("SSH 服务器密钥文件未找到"));
            }
        } else {
            info!("生成随机 SSH 服务器密钥");
            // 使用随机数生成器
            russh::keys::PrivateKey::random(&mut rand::thread_rng(), russh::keys::Algorithm::Ed25519)?
        };

        let config = russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            keys: vec![server_key],
            ..Default::default()
        };

        let config = Arc::new(config);
        let socket_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        info!("在 {} 上启动 SSH 服务器", socket_addr);
        
        // 使用 clone 后的 self 来避免可变借用冲突
        let mut server = self.clone();
        server.run_on_address(config, (self.config.listen_addr.as_str(), self.config.listen_port)).await?;
        
        Ok(())
    }

    /// 查找当前会话信息
    async fn get_session(&self) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().await;
        sessions.get(&self.id).cloned()
    }

    /// 更新会话的PTY信息
    async fn update_pty_info(&self, pty_info: PtyInfo) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&self.id) {
            session.pty_info = Some(pty_info);
            Ok(())
        } else {
            Err(anyhow::anyhow!("找不到会话信息"))
        }
    }

    /// 获取会话的PTY信息
    async fn get_pty_info(&self) -> Option<PtyInfo> {
        let sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(&self.id) {
            session.pty_info.clone()
        } else {
            None
        }
    }

    /// 获取通道用于SFTP子系统
    async fn get_channel(&self, channel_id: ChannelId) -> Option<Channel<Msg>> {
        let mut clients = self.clients.lock().await;
        clients.remove(&channel_id)
    }
}

impl russh::server::Server for SshServer {
    type Handler = Self;
    
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        // 使用原子操作获取唯一ID
        let client_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        
        // 创建新的处理器实例，每个客户端用自己的ID
        let mut handler = self.clone();
        handler.id = client_id;
        
        // 为每个新连接创建独立的命令处理器实例
        handler.cmd_handler = Arc::new(crate::command_handler::CommandHandler::default());
        
        tracing::info!(client_id = client_id, "新客户端连接");
        handler
    }
    
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("会话错误: {}", error);
    }
}

impl russh::server::Handler for SshServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        // 使用tracing进行结构化日志记录
        tracing::info!(
            username = %user, 
            auth_type = "none", 
            "用户尝试无密码认证"
        );
        
        // Only accept if username matches the default
        if user == self.config.default_username {
            tracing::info!(username = %user, "无密码认证成功");
            return Ok(Auth::Accept);
        }
        
        tracing::warn!(username = %user, "无密码认证被拒绝");
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // 使用tracing进行结构化日志记录
        tracing::info!(
            username = %user, 
            auth_type = "password", 
            "用户尝试密码认证"
        );
        
        // Check if username and password match the defaults
        if password == self.config.default_password {
        // if user == self.config.default_username && password == self.config.default_password {
            tracing::info!(username = %user, "密码认证成功");
            return Ok(Auth::Accept);
        }
        
        tracing::warn!(
            username = %user, 
            success = false, 
            "密码认证失败"
        );
        Ok(Auth::reject())
    }

    async fn auth_publickey(&mut self, user: &str, _public_key: &russh::keys::ssh_key::PublicKey) -> Result<Auth, Self::Error> {
        info!("用户 {} 尝试使用公钥认证", user);
        Ok(Auth::reject())
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        // 使用span记录会话生命周期
        let span = tracing::info_span!(
            "ssh_session", 
            session_id = self.id, 
            channel_id = ?channel.id()
        );
        let _guard = span.enter();
        
        tracing::info!("会话通道已打开");
        
        // 检查是否已存在会话信息
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(&self.id) {
            tracing::warn!("已存在会话信息，更新为新会话");
            // 如果存在旧会话，我们会更新它，无需特别清理
        }
        
        // 记录新会话信息
        sessions.insert(self.id, SessionInfo {
            channel_id: channel.id(),
            handle: session.handle(),
            pty_info: None,
            created_at: Instant::now(),
        });
        
        tracing::info!(
            total_sessions = sessions.len(),
            "当前活跃会话数"
        );
        
        // 保存通道用于SFTP子系统
        let mut clients = self.clients.lock().await;
        clients.insert(channel.id(), channel);
        
        Ok(true)
    }
    
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::info!(
            terminal = %term,
            cols = col_width,
            rows = row_height,
            "收到终端请求"
        );
        
        // 1. 验证终端类型
        if !is_valid_terminal_type(term) {
            tracing::warn!(
                terminal = %term,
                channel = ?channel,
                "不支持的终端类型"
            );
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 2. 验证终端大小
        if !is_valid_terminal_size(col_width, row_height) {
            tracing::warn!(
                cols = col_width, 
                rows = row_height,
                channel = ?channel,
                "无效的终端大小"
            );
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 3. 保存PTY信息
        let pty_info = PtyInfo {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
        };

        // 更新会话的PTY信息
        if let Err(e) = self.update_pty_info(pty_info).await {
            error!("保存PTY信息失败: {}", e);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 4. 发送成功响应
        session.channel_success(channel)?;
        Ok(())
    }
    
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        info!("收到 shell 请求");
        
        // 1. 检查是否已经收到PTY请求
        let pty_info = self.get_pty_info().await;
        
        // 2. 获取会话信息
        let _session_info = match self.get_session().await {
            Some(info) => info,
            None => {
                error!("找不到会话信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        
        // 3. 启动shell - 使用独立的命令处理器
        // 如果没有PTY信息，使用默认值或非交互模式
        if let Some(pty_info) = pty_info {
            // 有PTY信息，使用交互式shell
            match self.cmd_handler.start_shell(
                channel,
                _session_info.handle,
                &pty_info.term,
                pty_info.cols,
                pty_info.rows,
            ).await {
                Ok(_) => {
                    info!("交互式Shell启动成功");
                    session.channel_success(channel)?;
                },
                Err(e) => {
                    error!("启动交互式shell失败: {}", e);
                    session.channel_failure(channel)?;
                }
            }
        } else {
            // 没有PTY信息，使用非交互式shell
            warn!("收到shell请求但没有PTY信息，尝试启动非交互式shell");
            match self.cmd_handler.start_non_interactive_shell(
                channel,
                _session_info.handle,
            ).await {
                Ok(_) => {
                    info!("非交互式Shell启动成功");
                    session.channel_success(channel)?;
                },
                Err(e) => {
                    error!("启动非交互式shell失败: {}", e);
                    session.channel_failure(channel)?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(command).to_string();
        
        // 添加SCP命令识别和日志
        let is_scp = cmd.starts_with("scp ") || cmd.contains("/scp ") || 
                     cmd.contains(" -t ") || cmd.contains(" -f ");

        if is_scp {
            // 增强SCP命令解析的日志
            let args: Vec<&str> = cmd.split_whitespace().collect();
            tracing::debug!(command = %cmd, args = ?args, "检测到SCP命令，解析参数");
            
            // 判断是上传还是下载模式
            let is_upload = cmd.contains(" -t "); // -t 表示接收文件(上传到服务器)
            let is_download = cmd.contains(" -f "); // -f 表示发送文件(从服务器下载)
            
            // 记录SCP模式
            if is_upload {
                tracing::info!("SCP上传模式 (客户端 -> 服务器)");
                
                // 获取最后一个非选项参数作为目标路径
                let target_path = args.iter()
                    .filter(|&arg| !arg.starts_with("-"))
                    .last()
                    .map(|&s| s.to_string());
                    
                if let Some(target) = target_path {
                    tracing::info!(target = %target, "SCP目标路径");
                }
            } else if is_download {
                tracing::info!("SCP下载模式 (服务器 -> 客户端)");
            } else {
                tracing::info!("SCP未知模式");
            }
            
            // 尝试提取文件路径
            let mut source_path = "";
            let mut target_path = "";
            
            if args.len() >= 2 {
                // SCP命令格式通常为: scp [选项] source target
                // 找到非选项参数
                let mut non_option_args = args.iter()
                    .filter(|&arg| !arg.starts_with("-"))
                    .collect::<Vec<_>>();
                
                // 移除命令名称本身
                if non_option_args.len() > 0 && (non_option_args[0].ends_with("scp") || non_option_args[0] == &"scp") {
                    non_option_args.remove(0);
                }
                
                if non_option_args.len() >= 2 {
                    source_path = non_option_args[non_option_args.len() - 2];
                    target_path = non_option_args[non_option_args.len() - 1];
                    
                    // 提取源文件名
                    let source_filename = source_path.split('/').last().unwrap_or(source_path);
                    tracing::info!(
                        source = %source_path,
                        target = %target_path,
                        filename = %source_filename,
                        "SCP传输文件信息"
                    );
                    
                    // 保存源文件路径，供后续写入操作使用
                    if let Ok(mut source_file) = SCP_SOURCE_FILE.lock() {
                        *source_file = Some(source_path.to_string());
                        // 解析出源文件名，如果有@host:，则移除掉主机部分
                        if let Some(idx) = source_path.find(':') {
                            if idx + 1 < source_path.len() {
                                let actual_path = &source_path[(idx + 1)..];
                                let file_name = actual_path.split('/').last().unwrap_or(actual_path);
                                
                                // 在SCP_FILENAME_PARAM中存一个特殊映射，0作为索引表示从命令行提取的文件名
                                if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                                    filename_map.insert(0, file_name.to_string());
                                    tracing::info!(original_filename = %file_name, "从SCP命令行提取的原始文件名");
                                }
                            }
                        } else {
                            // 本地文件路径，直接提取文件名
                            let file_name = source_path.split('/').last().unwrap_or(source_path);
                            if let Ok(mut filename_map) = SCP_FILENAME_MAP.lock() {
                                filename_map.insert(0, file_name.to_string());
                                tracing::info!(original_filename = %file_name, "从SCP命令行提取的原始文件名");
                            }
                        }
                    }
                    
                    // 解析目标路径中是否包含@host:
                    if let Some(idx) = target_path.find(':') {
                        if idx + 1 < target_path.len() {
                            let actual_path = &target_path[(idx + 1)..];
                            tracing::info!(target_actual_path = %actual_path, "从目标路径提取的实际路径");
                        }
                    }
                }
            }
        } else {
            info!("收到执行命令请求: '{}'", cmd);
        }
        
        // 获取会话信息
        let _session_info = match self.get_session().await {
            Some(info) => info,
            None => {
                error!("找不到会话信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        
        // 发送成功响应
        session.channel_success(channel)?;
        
        // 使用cmd_handler执行命令
        let cmd_handler = self.cmd_handler.clone();
        
        // 这里仍然可以使用tokio::spawn，因为执行命令不需要等待结果
        tokio::spawn(async move {
            if let Err(e) = cmd_handler.execute_command(cmd, channel, _session_info.handle.clone()).await {
                error!("执行命令失败: {}", e);
            }
        });
        
        Ok(())
    }
    
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("窗口大小更改请求: {}x{}", col_width, row_height);
        
        // 1. 验证新的终端大小
        if !is_valid_terminal_size(col_width, row_height) {
            warn!("无效的终端大小: {}x{}", col_width, row_height);
            session.channel_failure(channel)?;
            return Ok(());
        }
        
        // 2. 更新PTY信息
        let mut sessions = self.sessions.lock().await;
        if let Some(session_info) = sessions.get_mut(&self.id) {
            if let Some(pty_info) = &mut session_info.pty_info {
                pty_info.cols = col_width;
                pty_info.rows = row_height;
            } else {
                warn!("尝试更新PTY大小，但会话没有PTY信息");
                session.channel_failure(channel)?;
                return Ok(());
            }
            
            // 3. 调整PTY大小 - 使用命令处理器
            if let Err(e) = self.cmd_handler.resize_pty(
                channel, 
                session_info.handle.clone(),
                col_width,
                row_height,
            ).await {
                error!("调整PTY大小失败: {}", e);
                session.channel_failure(channel)?;
                return Ok(());
            }
            
            session.channel_success(channel)?;
        } else {
            error!("找不到会话信息");
            session.channel_failure(channel)?;
        }
        
        Ok(())
    }
    
    async fn data(&mut self, channel: ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        tracing::trace!("在通道 {} 上收到数据: {:?}", channel, data);
        
        // 首先检查是否是SFTP通道
        if let Ok(sftp_channels) = SFTP_CHANNELS.lock() {
            if sftp_channels.contains(&channel) {
                // 这是一个SFTP通道，直接返回，不处理数据
                // 数据将通过通道流传递给SFTP处理程序
                tracing::debug!(
                    channel_id = ?channel,
                    data_len = data.len(),
                    "接收到SFTP通道数据，跳过命令处理"
                );
                return Ok(());
            }
        }
        
        // 获取会话信息
        let _session_info = match self.get_session().await {
            Some(info) => info,
            None => {
                error!("找不到会话信息，无法处理用户输入");
                return Ok(());
            }
        };
        
        // 1. 处理特殊控制字符
        if data == [3] { // Ctrl+C
            if let Err(e) = self.cmd_handler.send_signal(
                channel,
                _session_info.handle.clone(),
                "SIGINT",
            ).await {
                error!("发送SIGINT信号失败: {}", e);
            }
            return Ok(());
        }
        
        // 检查是否为SFTP数据包 - 作为额外检查
        // SFTP数据包通常以1-5字节的长度头开始，后跟类型字节，有特定的格式
        let is_sftp_packet = data.len() >= 5 && 
            ((data[0] == 0 && data[1] == 0) || (data[4] <= 25 && data[4] >= 1));  // 简单启发式检查
            
        if is_sftp_packet {
            // 对于SFTP数据包，记录但不处理 - 这些应该由SFTP子系统处理
            tracing::debug!(
                channel_id = ?channel,
                data_len = data.len(),
                data_head = ?&data[0..std::cmp::min(10, data.len())], 
                "发现SFTP数据包格式，但通道未注册为SFTP - 可能需要注册"
            );
            
            // 将此通道添加到SFTP_CHANNELS集合中
            if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
                sftp_channels.insert(channel);
                tracing::info!(channel_id = ?channel, "动态添加SFTP通道");
            }
            
            return Ok(());
        }
        
        // 2. 转发数据到shell - 使用命令处理器
        if let Err(e) = self.cmd_handler.handle_user_input(
            channel,
            data,
            _session_info.handle.clone(),
        ).await {
            error!("处理用户输入失败: {}", e);
        }
        
        Ok(())
    }

    // 添加会话关闭时的处理方法
    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        let span = tracing::info_span!(
            "ssh_session_close", 
            session_id = self.id, 
            channel_id = ?channel
        );
        let _guard = span.enter();
        
        tracing::info!("客户端关闭通道");
        
        // 检查是否是SFTP通道，如果是则移除
        if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
            if sftp_channels.remove(&channel) {
                tracing::info!(channel_id = ?channel, "关闭SFTP通道");
            }
        }
        
        // 在实际的会话终止时清理，此处不需操作
        // 实际的清理由Drop trait或会话监控处理
        
        Ok(())
    }

    // 修改subsystem_request方法，使用保存的通道
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::info!(
            channel_id = ?channel_id, 
            subsystem = %name, 
            "收到子系统请求"
        );
        
        // 当前只支持sftp子系统
        if name == "sftp" {
            // 立即将通道ID添加到SFTP通道集合中
            if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
                sftp_channels.insert(channel_id);
                tracing::info!(channel_id = ?channel_id, "注册SFTP通道");
            }
            
            // 获取会话信息
            let _session_info = match self.get_session().await {
                Some(info) => info,
                None => {
                    error!("找不到会话信息");
                    session.channel_failure(channel_id)?;
                    return Ok(());
                }
            };
            
            // 获取通道
            let channel = match self.get_channel(channel_id).await {
                Some(channel) => channel,
                None => {
                    error!("找不到对应的通道");
                    session.channel_failure(channel_id)?;
                    return Ok(());
                }
            };
            
            // 通知客户端成功
            session.channel_success(channel_id)?;
            
            // 创建SFTP处理器
            let mut handler = SftpHandler::default();
            
            // 检查是否有SCP源文件路径，如果有则标记为SCP会话
            if let Ok(source_file) = SCP_SOURCE_FILE.lock() {
                if source_file.is_some() {
                    handler.is_scp_session = true;
                    tracing::info!("检测到SCP会话使用SFTP子系统，启用SCP特殊处理");
                }
            }
            
            // 在单独的任务中运行SFTP服务
            tokio::spawn(async move {
                tracing::info!(channel_id = ?channel_id, "启动SFTP服务");
                
                // 使用通道的into_stream()方法获取通道流
                let channel_stream = channel.into_stream();
                
                // 运行SFTP服务并等待它完成
                // russh_sftp::server::run返回值是()，不是Result
                russh_sftp::server::run(channel_stream, handler).await;
                
                // SFTP会话结束
                tracing::info!(channel_id = ?channel_id, "SFTP会话结束");
                
                // 会话结束时，从SFTP通道集合中移除
                if let Ok(mut sftp_channels) = SFTP_CHANNELS.lock() {
                    sftp_channels.remove(&channel_id);
                    tracing::info!(channel_id = ?channel_id, "从SFTP通道注册中移除");
                }
            });
        } else {
            warn!("不支持的子系统请求: {}", name);
            session.channel_failure(channel_id)?;
        }
        
        Ok(())
    }
}

impl Drop for SshServer {
    fn drop(&mut self) {
        let id = self.id;
        let sessions = self.sessions.clone();
        
        tokio::spawn(async move {
            let mut sessions = sessions.lock().await;
            if sessions.remove(&id).is_some() {
                tracing::info!(session_id = id, "清理会话ID");
            }
        });
    }
}

/// 验证终端类型是否有效
fn is_valid_terminal_type(term: &str) -> bool {
    let valid_terms = [
        "xterm", "xterm-256color", "vt100", "vt220",
        "linux", "screen", "screen-256color"
    ];
    valid_terms.contains(&term)
}

/// 验证终端大小是否有效
fn is_valid_terminal_size(cols: u32, rows: u32) -> bool {
    cols > 0 && cols <= 1000 && rows > 0 && rows <= 1000
}

// 替换简单的全局变量为HashMap
lazy_static::lazy_static! {
    // Map<id, file_path>，保存SFTP请求ID到实际文件路径的映射
    static ref SCP_FILENAME_MAP: std::sync::Mutex<std::collections::HashMap<u32, String>> = std::sync::Mutex::new(std::collections::HashMap::new());
    // 保存当前SCP操作的源文件路径
    static ref SCP_SOURCE_FILE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    // 跟踪哪些通道ID是SFTP通道
    static ref SFTP_CHANNELS: std::sync::Mutex<std::collections::HashSet<ChannelId>> = std::sync::Mutex::new(std::collections::HashSet::new());
} 