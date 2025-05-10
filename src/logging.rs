//! 日志系统模块，提供统一的日志初始化和辅助函数

use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use tracing::Level;
use std::sync::Once;

// 确保日志系统只初始化一次
static INIT: Once = Once::new();

/// 日志系统初始化函数
/// 
/// # 参数
/// * `default_level` - 默认日志级别
/// * `app_name` - 应用名称, 用于环境变量前缀
/// 
/// # 示例
/// ```
/// use ssh_proxy::setup_logging;
/// 
/// // 默认使用 INFO 级别，可通过 SSH_PROXY_LOG 环境变量覆盖
/// setup_logging(tracing::Level::INFO, "SSH_PROXY");
/// ```
pub fn setup_logging(default_level: Level, app_name: &str) {
    // 使用Once确保日志系统只初始化一次
    INIT.call_once(|| {
        // 构建环境变量名
        let env_name = format!("{}_LOG", app_name);
        
        // 构建默认指令
        let default_directive = match default_level {
            Level::TRACE => "trace",
            Level::DEBUG => "debug",
            Level::INFO => "info",
            Level::WARN => "warn",
            Level::ERROR => "error",
        };
        
        // 从环境变量设置日志级别，默认指定的级别
        let filter = EnvFilter::try_from_env(env_name)
            .unwrap_or_else(|_| {
                // ssh_proxy=debug 意味着我们的代码使用DEBUG级别，依赖库使用默认级别
                EnvFilter::new(format!("{},ssh_proxy={}", default_directive, default_directive))
            });
        
        // 设置控制台日志格式
        let fmt_layer = fmt::layer()
            .with_target(true)     // 显示目标模块
            .with_thread_ids(true) // 在多线程环境中显示线程ID
            .with_file(true)       // 显示文件名
            .with_line_number(true); // 显示行号
        
        // 使用JSON格式作为可选，通过环境变量启用
        if std::env::var(format!("{}_JSON", app_name)).is_ok() {
            // 必须先初始化LogTracer，确保log crate的消息能被正确处理
            if let Ok(()) = tracing_log::LogTracer::init() {
                // 只有在LogTracer初始化成功后才能设置subscriber
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json())
                    .try_init()
                    .ok(); // 忽略可能的错误，因为可能在测试中已经初始化
            }
        } else {
            // 必须先初始化LogTracer，确保log crate的消息能被正确处理
            if let Ok(()) = tracing_log::LogTracer::init() {
                // 使用普通文本格式
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .try_init()
                    .ok(); // 忽略可能的错误
            }
        }
        
        // 记录启动日志
        tracing::info!("日志系统初始化完成 [{} {}]", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_setup_logging() {
        // 测试环境下，只是确保函数不会panic
        setup_logging(Level::DEBUG, "TEST");
        tracing::debug!("测试日志记录");
    }
} 