use std::os::unix::fs::MetadataExt;
use std::sync::Mutex as StdMutex;

use russh::ChannelId;
use russh_sftp::protocol::OpenFlags;
use tracing;

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

// 跟踪哪些通道ID是SFTP通道
lazy_static::lazy_static! {
    // 使用(会话ID, 通道ID)元组作为键，确保即使通道ID相同但会话不同也能区分
    pub static ref SFTP_CHANNELS: StdMutex<std::collections::HashSet<(usize, ChannelId)>> = 
        StdMutex::new(std::collections::HashSet::new());
}

/// SFTP 处理器结构体
#[derive(Default)]
pub struct SftpHandler {
    root_dir_read_done: bool,
}

impl SftpHandler {
    /// 从文件元数据创建SFTP文件属性
    fn create_file_attributes(&self, metadata: &std::fs::Metadata) -> russh_sftp::protocol::FileAttributes {
        let mut attrs = russh_sftp::protocol::FileAttributes::default();
        
        // 设置基本属性
        attrs.size = Some(metadata.len());
        attrs.uid = Some(metadata.uid());
        attrs.gid = Some(metadata.gid());
        attrs.atime = Some(metadata.atime() as u32);
        attrs.mtime = Some(metadata.mtime() as u32);
        
        // 设置文件类型和权限
        let permissions = if metadata.is_dir() {
            SFTP_TYPE_DIRECTORY | PERM_DIRECTORY
        } else if metadata.is_file() {
            SFTP_TYPE_REGULAR | PERM_FILE
        } else if metadata.file_type().is_symlink() {
            SFTP_TYPE_SYMLINK | PERM_FILE
        } else if cfg!(unix) {
            let file_type = metadata.file_type();
            if std::os::unix::fs::FileTypeExt::is_socket(&file_type) {
                SFTP_TYPE_SOCKET | PERM_FILE
            } else if std::os::unix::fs::FileTypeExt::is_char_device(&file_type) {
                SFTP_TYPE_CHAR | PERM_FILE
            } else if std::os::unix::fs::FileTypeExt::is_block_device(&file_type) {
                SFTP_TYPE_BLOCK | PERM_FILE
            } else if std::os::unix::fs::FileTypeExt::is_fifo(&file_type) {
                SFTP_TYPE_FIFO | PERM_FILE
            } else {
                SFTP_TYPE_REGULAR | PERM_FILE
            }
        } else {
            SFTP_TYPE_REGULAR | PERM_FILE
        };
        
        attrs.permissions = Some(permissions);
        
        // 如果在Unix系统上，获取POSIX文件权限
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            // 保留文件类型位，并合并POSIX权限位
            attrs.permissions = Some((attrs.permissions.unwrap_or(0) & 0xF000) | (mode & 0xFFF));
        }
        
        attrs
    }
    
    /// 设置文件的访问时间和修改时间
    fn set_file_times(&self, path: &str, atime: Option<u32>, mtime: Option<u32>) -> std::io::Result<()> {
        // 如果没有提供时间，不进行修改
        if atime.is_none() && mtime.is_none() {
            return Ok(());
        }
        
        #[cfg(unix)]
        {
            // 在 Unix 系统上，我们可以使用 std::process::Command 执行 touch 命令来设置文件时间
            use std::process::Command;
            
            // 收集所有参数
            let mut cmd = Command::new("touch");
            cmd.arg("-c"); // -c 表示不创建文件
            
            // 为访问时间和修改时间创建单独的子命令
            if let Some(at) = atime {
                // 格式化时间为 [[CC]YY]MMDDhhmm[.SS] 格式，这里简化处理
                let time_str = format!("{}01010000.00", at / (60*60*24*365) + 1970);
                cmd.arg("-a").arg("-t").arg(time_str);
            }
            
            if let Some(mt) = mtime {
                // 格式化时间为 [[CC]YY]MMDDhhmm[.SS] 格式，这里简化处理
                let time_str = format!("{}01010000.00", mt / (60*60*24*365) + 1970);
                cmd.arg("-m").arg("-t").arg(time_str);
            }
            
            cmd.arg(path);
            
            let output = cmd.output()?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("设置文件时间失败: {}", stderr)
                ));
            }
            
            Ok(())
        }
        
        #[cfg(not(unix))]
        {
            tracing::warn!(path = %path, "设置文件时间戳在非Unix系统上不支持");
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "设置文件时间戳在非Unix系统上不支持"))
        }
    }
    
    /// 设置文件的所有者和组
    fn set_file_owner(&self, path: &str, uid: Option<u32>, gid: Option<u32>) -> std::io::Result<()> {
        // 如果没有提供uid和gid，不进行修改
        if uid.is_none() && gid.is_none() {
            return Ok(());
        }
        
        #[cfg(unix)]
        {
            // 在 Unix 系统上，我们可以使用 std::process::Command 执行 chown 命令来设置文件所有者
            use std::process::Command;
            
            // 构造 owner:group 格式的字符串
            let mut owner_str = String::new();
            
            if let Some(u) = uid {
                owner_str.push_str(&u.to_string());
            }
            
            if let Some(g) = gid {
                owner_str.push(':');
                owner_str.push_str(&g.to_string());
            } else if !owner_str.is_empty() {
                // 如果只指定了 uid 但没有 gid，需要加上冒号表示不修改组
                owner_str.push(':');
            }
            
            let output = Command::new("chown")
                .arg(owner_str)
                .arg(path)
                .output()?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("设置文件所有者失败: {}", stderr)
                ));
            }
            
            Ok(())
        }
        
        #[cfg(not(unix))]
        {
            tracing::warn!(path = %path, "设置文件所有者在非Unix系统上不支持");
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "设置文件所有者在非Unix系统上不支持"))
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
        Ok(russh_sftp::protocol::Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP realpath请求");
        
        // 规范化路径
        let normalized_path = if path.is_empty() || path == "." {
            ".".to_string()
        } else {
            path.clone()
        };
        
        // 获取文件属性
        let attrs = match std::fs::metadata(&normalized_path) {
            Ok(metadata) => self.create_file_attributes(&metadata),
            Err(err) => {
                tracing::error!(path = %normalized_path, error = %err, "无法获取文件属性");
                return Err(russh_sftp::protocol::StatusCode::NoSuchFile);
            }
        };
        
        Ok(russh_sftp::protocol::Name {
            id,
            files: vec![russh_sftp::protocol::File::new(&normalized_path, attrs)],
        })
    }
    
    async fn opendir(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP opendir请求");
        self.root_dir_read_done = false;
        Ok(russh_sftp::protocol::Handle { id, handle: path })
    }
    
    async fn readdir(&mut self, id: u32, handle: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        tracing::info!(id = id, handle = %handle, "SFTP readdir请求");
        
        // 使用handle作为目录路径
        let path = handle;
        
        // 检查目录是否存在
        if !std::path::Path::new(&path).is_dir() {
            tracing::error!(id = id, path = %path, "路径不是目录");
            return Err(russh_sftp::protocol::StatusCode::NoSuchFile);
        }
        
        // 读取目录内容
        match std::fs::read_dir(&path) {
            Ok(entries) => {
                let mut files = Vec::new();
                
                // 添加 "." 和 ".." 条目
                if let Ok(metadata) = std::fs::metadata(&path) {
                    // 当前目录的属性
                    let current_dir_attrs = self.create_file_attributes(&metadata);
                    files.push(russh_sftp::protocol::File::new(".", current_dir_attrs));
                    
                    // 父目录的属性
                    let parent_path = std::path::Path::new(&path).parent().unwrap_or(std::path::Path::new("/"));
                    if let Ok(parent_metadata) = std::fs::metadata(parent_path) {
                        let parent_attrs = self.create_file_attributes(&parent_metadata);
                        files.push(russh_sftp::protocol::File::new("..", parent_attrs));
                    } else {
                        // 如果无法获取父目录元数据，使用当前目录的属性作为后备
                        let fallback_attrs = self.create_file_attributes(&metadata);
                        files.push(russh_sftp::protocol::File::new("..", fallback_attrs));
                    }
                }
                
                // 添加目录中的所有文件和子目录
                for entry_result in entries {
                    match entry_result {
                        Ok(entry) => {
                            if let Ok(file_name) = entry.file_name().into_string() {
                                match entry.metadata() {
                                    Ok(metadata) => {
                                        // 使用辅助方法创建文件属性
                                        let attrs = self.create_file_attributes(&metadata);
                                        
                                        // 添加文件条目
                                        files.push(russh_sftp::protocol::File::new(&file_name, attrs));
                                    },
                                    Err(e) => {
                                        tracing::warn!(path = %path, file = %file_name, error = %e, "无法获取文件元数据");
                                        // 继续处理下一个文件
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            tracing::warn!(path = %path, error = %e, "读取目录条目失败");
                            // 继续处理下一个文件
                        }
                    }
                }
                
                return Ok(russh_sftp::protocol::Name {
                    id,
                    files,
                });
            },
            Err(e) => {
                tracing::error!(id = id, path = %path, error = %e, "读取目录失败");
                return Err(russh_sftp::protocol::StatusCode::Failure);
            }
        }
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
                let attrs = self.create_file_attributes(&metadata);
                Ok(russh_sftp::protocol::Attrs { id, attrs })
            },
            Err(e) => {
                tracing::warn!(id = id, path = %path, error = %e, "SFTP stat请求失败");
                // 根据错误类型返回相应的SFTP状态码
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        return Err(russh_sftp::protocol::StatusCode::NoSuchFile);
                    },
                    std::io::ErrorKind::PermissionDenied => {
                        return Err(russh_sftp::protocol::StatusCode::PermissionDenied);
                    },
                    std::io::ErrorKind::InvalidInput => {
                        return Err(russh_sftp::protocol::StatusCode::BadMessage);
                    },
                    _ => {
                        return Err(russh_sftp::protocol::StatusCode::Failure);
                    }
                }
            }
        }
    }
    
    // 添加lstat操作支持(与stat类似，但不解析符号链接)
    async fn lstat(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        tracing::info!(id = id, path = %path, "SFTP lstat请求");
        
        // 使用symlink_metadata而不是metadata，这样不会跟随符号链接
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                let attrs = self.create_file_attributes(&metadata);
                Ok(russh_sftp::protocol::Attrs { id, attrs })
            },
            Err(e) => {
                tracing::warn!(id = id, path = %path, error = %e, "SFTP lstat请求失败");
                // 根据错误类型返回相应的SFTP状态码
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        return Err(russh_sftp::protocol::StatusCode::NoSuchFile);
                    },
                    std::io::ErrorKind::PermissionDenied => {
                        return Err(russh_sftp::protocol::StatusCode::PermissionDenied);
                    },
                    std::io::ErrorKind::InvalidInput => {
                        return Err(russh_sftp::protocol::StatusCode::BadMessage);
                    },
                    _ => {
                        return Err(russh_sftp::protocol::StatusCode::Failure);
                    }
                }
            }
        }
    }
    
    // 添加open操作支持
    async fn open(&mut self, id: u32, path: String, pflags: OpenFlags, _attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        tracing::info!(id = id, path = %path, pflags = ?pflags, "SFTP open请求");
        
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
                // 如果是读取操作，可以正常打开目录
                return Ok(russh_sftp::protocol::Handle { id, handle: path });
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
        
        // 打开文件用于写入
        match std::fs::OpenOptions::new()
            .write(true)
            .open(&handle) {
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
                let attrs = self.create_file_attributes(&metadata);
                Ok(russh_sftp::protocol::Attrs { id, attrs })
            },
            Err(e) => {
                tracing::warn!(id = id, handle = %handle, error = %e, "SFTP fstat请求失败");
                Err(russh_sftp::protocol::StatusCode::Failure)
            }
        }
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

    // 添加 fsetstat 操作支持 - 设置文件属性
    async fn fsetstat(&mut self, id: u32, handle: String, attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, handle = %handle, ?attrs, "SFTP fsetstat请求");
        
        // 检查文件是否存在
        if !std::path::Path::new(&handle).exists() {
            tracing::error!(id = id, handle = %handle, "文件不存在");
            return Err(russh_sftp::protocol::StatusCode::NoSuchFile);
        }
        
        // 应用文件属性修改
        let mut success = true;
        
        // 修改文件时间戳
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            if let Err(e) = self.set_file_times(&handle, attrs.atime, attrs.mtime) {
                tracing::error!(id = id, handle = %handle, error = %e, "设置文件时间戳失败");
                success = false;
            }
        }
        
        // 修改文件权限
        #[cfg(unix)]
        if let Some(permissions) = attrs.permissions {
            use std::os::unix::fs::PermissionsExt;
            // 只获取权限位 (去掉文件类型位)
            let mode = permissions & 0o777;
            if let Err(e) = std::fs::set_permissions(&handle, std::fs::Permissions::from_mode(mode)) {
                tracing::error!(id = id, handle = %handle, mode = %format!("{:o}", mode), error = %e, "设置文件权限失败");
                success = false;
            }
        }
        
        // 修改文件所有者和组
        #[cfg(unix)]
        if attrs.uid.is_some() || attrs.gid.is_some() {
            if let Err(e) = self.set_file_owner(&handle, attrs.uid, attrs.gid) {
                tracing::error!(id = id, handle = %handle, uid = ?attrs.uid, gid = ?attrs.gid, error = %e, "设置文件所有者失败");
                success = false;
            }
        }
        
        if success {
            Ok(russh_sftp::protocol::Status {
                id,
                status_code: russh_sftp::protocol::StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            })
        } else {
            Err(russh_sftp::protocol::StatusCode::Failure)
        }
    }
    
    // 添加 setstat 操作支持 - 设置文件属性
    async fn setstat(&mut self, id: u32, path: String, attrs: russh_sftp::protocol::FileAttributes) -> Result<russh_sftp::protocol::Status, Self::Error> {
        tracing::info!(id = id, path = %path, ?attrs, "SFTP setstat请求");
        
        // 直接调用 fsetstat 实现
        self.fsetstat(id, path, attrs).await
    }
} 