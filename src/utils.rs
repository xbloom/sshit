#[allow(unused_imports)]
use anyhow::{Result, anyhow, Context};
#[allow(unused_imports)]
use tracing::{error, warn, debug, info};
#[allow(unused_imports)]
use std::fmt::Display;

/// 🚀 超级简洁的错误处理宏
/// 
/// 用法: `e!(expr, "错误信息")?`
/// 
/// 简单明了的错误处理方式
/// 
/// # 示例
/// ```
/// # use anyhow::{Result, anyhow};
/// # use tracing::error;
/// # use ssh_proxy::e;
/// # fn example() -> Result<()> {
/// let result = e!(std::fs::read_to_string("non-existent.txt"), "读取文件失败")?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! e {
    // 基本用法: e!(表达式, "错误消息")?
    ($e:expr, $msg:expr) => {
        $e.map_err(|e| {
            error!("{}: {}", $msg, e);
            anyhow!("{}: {}", $msg, e)
        })
    };
    
    // 格式化用法: e!(表达式, "格式化消息 {}", 变量)?
    ($e:expr, $fmt:expr, $($arg:tt)*) => {
        $e.map_err(|e| {
            let msg = format!($fmt, $($arg)*);
            error!("{}: {}", msg, e);
            anyhow!("{}: {}", msg, e)
        })
    };
}

/// 🧠 智能错误处理器 - 带自动恢复功能
/// 
/// 允许在出错时自动尝试恢复
/// 
/// # 示例
/// ```
/// # use anyhow::Result;
/// # use tracing::error;
/// # use ssh_proxy::try_or;
/// # fn example() -> Result<()> {
/// // 基本用法，失败时返回默认值
/// let file_content = try_or!(std::fs::read_to_string("config.txt"), String::new());
/// 
/// // 带日志的版本
/// let config = try_or!(std::fs::read_to_string("config.txt"), 
///                     "default-config".to_string(), 
///                     "读取配置文件失败");
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! try_or {
    // 基本版本 - 失败时返回默认值
    ($e:expr, $default:expr) => {
        match $e {
            Ok(v) => v,
            Err(_) => $default,
        }
    };
    
    // 带日志的版本
    ($e:expr, $default:expr, $msg:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                error!("{}: {}", $msg, e);
                $default
            }
        }
    };
}

/// 灵活的错误处理宏 - 支持不同日志级别
/// 
/// # 示例
/// ```
/// # use anyhow::{Result, anyhow};
/// # use tracing::{error, warn};
/// # use ssh_proxy::try_log;
/// # fn example() -> Result<()> {
/// // 默认error级别
/// let content = try_log!(std::fs::read_to_string("file.txt"), "读取文件失败")?;
/// 
/// // 指定warn级别
/// let config = try_log!(std::fs::read_to_string("config.txt"), 
///                     warn, "配置文件不存在，将使用默认值")?;
/// 
/// // 支持格式化
/// let file_path = "data.json";
/// let data = try_log!(std::fs::read_to_string(file_path), 
///                   error, "无法读取文件 {}", file_path)?;
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! try_log {
    // 基本用法: try_log!(expr, "消息")? - 默认error级别
    ($e:expr, $msg:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}: {}", $msg, e);
                Err(anyhow!("{}: {}", $msg, e))
            }
        }
    };
    
    // 指定日志级别: try_log!(expr, error|warn|debug|info, "消息")?
    ($e:expr, error, $msg:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("{}: {}", $msg, e);
                Err(anyhow!("{}: {}", $msg, e))
            }
        }
    };
    
    ($e:expr, warn, $msg:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                warn!("{}: {}", $msg, e);
                Err(anyhow!("{}: {}", $msg, e))
            }
        }
    };
    
    ($e:expr, debug, $msg:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                debug!("{}: {}", $msg, e);
                Err(anyhow!("{}: {}", $msg, e))
            }
        }
    };
    
    ($e:expr, info, $msg:expr) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                info!("{}: {}", $msg, e);
                Err(anyhow!("{}: {}", $msg, e))
            }
        }
    };
    
    // 支持格式化: try_log!(expr, error|warn|debug|info, "格式 {}", 变量)?
    ($e:expr, $level:ident, $fmt:expr, $($arg:tt)*) => {
        match $e {
            Ok(v) => Ok(v),
            Err(e) => {
                let msg = format!($fmt, $($arg)*);
                $level!("{}: {}", msg, e);
                Err(anyhow!("{}: {}", msg, e))
            }
        }
    };
} 