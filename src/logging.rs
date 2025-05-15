//! 日志系统模块，提供统一的日志初始化和辅助函数

use tracing_subscriber::{fmt, EnvFilter, prelude::*};
use tracing::Level;
use std::sync::Once;
use std::path::Path;
use time::{OffsetDateTime, format_description};
use regex::Regex;

// 确保日志系统只初始化一次
static INIT: Once = Once::new();

/// 自定义格式化器，只显示文件名而不是完整路径
struct CustomFormatter;

impl<S, N> fmt::FormatEvent<S, N> for CustomFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        // 使用time库格式化时间 - 压缩格式
        let now = OffsetDateTime::now_utc();
        let format = format_description::parse(
            "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
        ).unwrap_or_else(|_| format_description::parse("[hour]:[minute]:[second]").unwrap());
        let formatted_time = now.format(&format).unwrap_or_else(|_| String::from("unknown time"));
        write!(writer, "\x1b[90m{:<17}\x1b[0m ", formatted_time)?;  // 压缩日期格式

        // 格式化线程ID - 使用稳定的方法
        write!(writer, "\x1b[90m{:?}\x1b[0m ", std::thread::current().id())?;  // 使用稳定的线程信息

        // 格式化日志级别（带颜色）- 保持明亮
        let metadata = event.metadata();
        let level = *metadata.level();
        match level {
            Level::TRACE => write!(writer, "\x1b[95m{:<5}\x1b[0m", "TRACE")?,  // 紫色
            Level::DEBUG => write!(writer, "\x1b[96m{:<5}\x1b[0m", "DEBUG")?,  // 亮青色
            Level::INFO => write!(writer, "\x1b[92m{:<5}\x1b[0m", "INFO")?,   // 亮绿色
            Level::WARN => write!(writer, "\x1b[93m{:<5}\x1b[0m", "WARN")?,   // 亮黄色
            Level::ERROR => write!(writer, "\x1b[91m{:<5}\x1b[0m", "ERROR")?,  // 亮红色
        }
        write!(writer, " ")?;

        // 获取并显示span上下文信息 - 使用淡青色显示
        if let Some(span) = ctx.lookup_current() {
            let mut span_color = "\x1b[38;5;116m"; // 淡青色
            write!(writer, "[")?;
            
            // 获取span名称并显示
            let name = span.name();
            if !name.is_empty() {
                write!(writer, "{}{}\x1b[0m", span_color, name)?;
            }
            
            // 遍历span中的扩展数据，显示会话ID和通道ID等
            let mut extensions = span.extensions_mut();
            if let Some(fields) = extensions.get_mut::<fmt::FormattedFields<N>>() {
                if !fields.fields.is_empty() {
                    if !name.is_empty() {
                        write!(writer, " ")?;
                    }
                    span_color = "\x1b[38;5;159m"; // 换个颜色区分字段
                    write!(writer, "{}{}\x1b[0m", span_color, fields.fields)?;
                }
            }
            // 在访问完extensions后，释放对span的可变借用
            drop(extensions);
            
            // 添加上级span的信息 - 不修改当前span的引用
            let parent_span_info = get_parent_info(&span);
            if !parent_span_info.is_empty() {
                span_color = "\x1b[38;5;110m"; // 更淡的蓝色表示父span
                write!(writer, " <- {}{}\x1b[0m", span_color, parent_span_info)?;
            }
            
            write!(writer, "] ")?;
        }

        // 格式化文件名和行号 - 淡蓝色
        if let Some(file) = metadata.file() {
            let file_name = Path::new(file)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(file);
            if let Some(line) = metadata.line() {
                write!(writer, "\x1b[38;5;153m{:<15}:{:<4}\x1b[0m: ", file_name, line)?;  // 淡蓝色，固定宽度
            } else {
                write!(writer, "\x1b[38;5;153m{:<15}\x1b[0m: ", file_name)?;  // 淡蓝色，固定宽度
            }
        }

        // 格式化字段（日志内容）- 变量用彩虹色，普通内容用亮金色
        let mut field_buf = String::new();
        let field_writer = fmt::format::Writer::new(&mut field_buf);
        ctx.field_format().format_fields(field_writer, event)?;

        let rainbow_colors = [
            "\x1b[38;5;224m", // 更淡橙
            "\x1b[38;5;194m", // 更淡绿
            "\x1b[38;5;195m", // 更淡蓝
            "\x1b[38;5;225m", // 更淡紫
            "\x1b[38;5;230m", // 更淡黄
            "\x1b[38;5;159m", // 淡青
        ];
        let mut color_index = 0;
        let re = Regex::new(r"\b([\w\-]+)=([^\s]+)").unwrap();
        let mut last = 0;
        let mut formatted = String::new();
        let mut first_var = true;
        for cap in re.captures_iter(&field_buf) {
            let m = cap.get(0).unwrap();
            // 普通内容（变量前）
            if m.start() > last {
                let normal = &field_buf[last..m.start()];
                if !normal.trim().is_empty() {
                    formatted.push_str("\x1b[1m\x1b[38;5;228m");
                    formatted.push_str(normal);
                    formatted.push_str("\x1b[0m");
                }
            }
            // 变量内容
            if !first_var {
                formatted.push(' ');
            }
            first_var = false;
            let color = rainbow_colors[color_index % rainbow_colors.len()];
            color_index += 1;
            formatted.push_str(color);
            formatted.push_str(&cap[1]);
            formatted.push_str("=\x1b[0m");
            formatted.push_str(color);
            formatted.push_str(&cap[2]);
            formatted.push_str("\x1b[0m");
            last = m.end();
        }
        // 剩余普通内容
        if last < field_buf.len() {
            let normal = &field_buf[last..];
            if !normal.trim().is_empty() {
                formatted.push_str("\x1b[1m\x1b[38;5;228m");
                formatted.push_str(normal);
                formatted.push_str("\x1b[0m");
            }
        }
        write!(writer, "{}", formatted)?;
        writeln!(writer)
    }
}

// 添加一个辅助函数来获取父span的信息
fn get_parent_info<S>(span: &tracing_subscriber::registry::SpanRef<'_, S>) -> String 
where 
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let mut result = String::new();
    let current = span; // 使用引用而不是克隆
    
    // 获取第一个父span
    if let Some(parent) = current.parent() {
        let mut current_parent = parent;
        loop {
            let parent_name = current_parent.name();
            if !parent_name.is_empty() {
                if !result.is_empty() {
                    result.push_str(" <- ");
                }
                result.push_str(parent_name);
            }
            
            // 尝试获取下一个父span
            match current_parent.parent() {
                Some(next_parent) => current_parent = next_parent,
                None => break,
            }
        }
    }
    
    result
}

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
                // 检查是否已通过RUST_LOG设置了日志级别
                match std::env::var("RUST_LOG") {
                    Ok(rust_log) => {
                        // 如果设置了RUST_LOG，使用它作为基础，但确保我们的包也有正确的日志级别
                        let combined = format!("{},ssh_proxy={}", rust_log, default_directive);
                        EnvFilter::new(combined)
                    },
                    Err(_) => {
                        // 没有设置RUST_LOG，使用默认设置
                        // ssh_proxy=debug 意味着我们的代码使用DEBUG级别，依赖库使用默认级别
                        EnvFilter::new(format!("{},ssh_proxy={},russh=warn", default_directive, default_directive))
                    }
                }
            });
        
        // 检查是否应该启用自定义格式化器和彩色日志
        let use_custom_formatter = std::env::var("COLORIZE_LOGS").is_ok();
        
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
                // 根据环境变量选择是否使用自定义格式化器
                if use_custom_formatter {
                    // 使用自定义格式化器并启用彩色输出
                    tracing_subscriber::registry()
                        .with(filter)
                        .with(fmt::layer().event_format(CustomFormatter).with_ansi(true))
                        .try_init()
                        .ok(); // 忽略可能的错误
                } else {
                    // 使用默认格式化器，简洁明了
                    tracing_subscriber::registry()
                        .with(filter)
                        .with(fmt::layer().with_ansi(false))
                        .try_init()
                        .ok(); // 忽略可能的错误
                }
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