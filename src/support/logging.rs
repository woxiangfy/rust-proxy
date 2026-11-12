//! Logging module for initializing logger with rotation support

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Result;
use env_logger::Builder;
use log::LevelFilter;
use serde::Deserialize;

/// 日志级别
///
/// 定义在本模块而非 `config`：日志级别是日志域的取值域，放在 `config` 会让
/// `logging` 反向依赖配置模块（仅为这一个枚举）。`config` 侧以 `pub use`
/// 重新导出，`config::LogLevel` 路径保持可用。
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Warn,
    Error,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(LogLevel::Trace),
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" => Ok(LogLevel::Warn),
            "error" => Ok(LogLevel::Error),
            _ => Err(format!("Invalid log level: {}", s)),
        }
    }
}

/// 日志文件最大大小（10 MB），超过后自动分割
const MAX_LOG_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// 最多保留的日志文件数量（含当前活动文件）
const MAX_LOG_FILES: usize = 10;

/// 惰性缓存本地时区偏移（秒），避免每次写日志都做一次时区查询。
///
/// 时区极少在进程运行期间变化；每次写日志都查一次会成为高并发写日志时的热路径开销，
/// 因此用 `OnceLock` 缓存首次结果。
///
/// 代价是：进程跨夏令时切换长期运行时缓存值不跟着变（时间戳会偏 1 小时，重启即恢复）。
/// 这是刻意取舍——日志时间的用途是"排序 + 大致定位"，而每次写日志都调系统时区接口更贵。
static TZ_OFFSET_SECONDS: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// 本地时区偏移（秒）
///
/// 由 `time` crate 提供跨平台实现（Windows 走 `GetTimeZoneInformation`、
/// Unix 走 `localtime_r`），项目自己不再维护 FFI 与 `unsafe`。
fn local_offset_seconds() -> i32 {
    *TZ_OFFSET_SECONDS.get_or_init(|| {
        time::UtcOffset::current_local_offset()
            .map(|off| off.whole_seconds())
            // 拿不到本地时区（如容器缺 tzdata）时按 UTC 记录：时间仍正确可排序，
            // 只是不带本地偏移。
            .unwrap_or(0)
    })
}

/// 带缓存的本地时区偏移对象
fn local_offset() -> time::UtcOffset {
    time::UtcOffset::from_whole_seconds(local_offset_seconds()).unwrap_or(time::UtcOffset::UTC)
}

/// 当前本地时间
///
/// 必须用 [`time::OffsetDateTime::to_offset`]（只切换表述时区，**不改变时间点**），
/// 不能用 `now_utc() + Duration`——后者会把时刻本身平移一个时区偏移，
/// 导致 `unix_timestamp()` 与系统时钟差出整整 8 小时（已有测试固定该语义）。
fn now_local() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc().to_offset(local_offset())
}

/// 获取当前本地时间的 (年, 月, 日, 时, 分, 秒) 元组
fn get_local_datetime() -> (i32, u8, u8, u8, u8, u8) {
    let t = now_local();
    (
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

/// 生成用于存档文件名的时间戳后缀，格式 YYYYMMDD_HHMMSS（如 20260814_153045）
fn get_timestamp_suffix() -> String {
    let (year, month, day, hours, minutes, seconds) = get_local_datetime();
    format!(
        "{:04}{:02}{:02}_{:02}{:02}{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// 滚动日志写入器的内部状态
struct RollingWriterInner {
    base_path: PathBuf,
    current_file: Option<File>,
    current_size: u64,
    max_size: u64,
    max_files: usize,
}

/// 按文件大小滚动的日志写入器，实现了 `Write` trait
///
/// 当前日志文件大小超过 `max_size` 时，自动将文件重命名为带时间戳后缀的存档文件
/// （如 proxy.20260814_153045.log），并创建新日志文件继续写入。
/// 自动清理超过 `max_files` 个的历史存档。
pub struct RollingWriter {
    inner: Mutex<RollingWriterInner>,
}

impl RollingWriter {
    /// 创建一个新的 `RollingWriterBuilder` 构建器
    pub fn builder<P: AsRef<Path>>(path: P) -> RollingWriterBuilder {
        RollingWriterBuilder::new(path)
    }
}

/// 执行日志滚动：关闭当前文件句柄，重命名为存档文件，创建新文件
fn rotate(inner: &mut RollingWriterInner) -> io::Result<()> {
    let base_path = inner.base_path.clone();

    let file_name = base_path
        .file_name()
        .expect("log path must have a file name")
        .to_string_lossy()
        .to_string();
    let ts = get_timestamp_suffix();
    let rotated = unique_rotated_path(&base_path, &file_name, &ts);

    // 先关闭旧文件句柄，再重命名（Windows 上文件被占用时 rename 会失败）
    let _ = inner.current_file.take();

    if let Err(e) = fs::rename(&base_path, &rotated) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e);
        }
    }

    let new_file = open_log_file(&base_path)?;
    inner.current_file = Some(new_file);
    inner.current_size = 0;

    Ok(())
}

/// 生成唯一的存档文件路径
/// 格式：{stem}.{timestamp}.{ext}（如 proxy.20260814_153045.log）
/// 若文件已存在，则追加序号：{stem}.{timestamp}.{ext}.1
fn unique_rotated_path(base_path: &Path, file_name: &str, ts: &str) -> PathBuf {
    let dir = base_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);
    let ext = path.extension().and_then(|e| e.to_str());

    let rotated_name = match ext {
        Some(ext) => format!("{}.{}.{}", stem, ts, ext),
        None => format!("{}.{}", stem, ts),
    };

    let candidate = dir.join(&rotated_name);
    if !candidate.exists() {
        return candidate;
    }
    // 若文件已存在，追加递增序号
    for i in 1.. {
        let candidate = dir.join(format!("{}.{}", rotated_name, i));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

macro_rules! impl_write_for {
    ($ty:ty) => {
        impl Write for $ty {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                // 锁 poison 容错：滚动写入器临界区极短，panic 后继续使用内部状态
                let mut inner = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(e) => e.into_inner(),
                };

                let file = inner
                    .current_file
                    .as_mut()
                    .expect("current log file is closed");
                let n = file.write(buf)?;
                inner.current_size += n as u64;

                // 写入后检查：超限则滚动（同一锁内完成，避免重复加锁）
                if inner.current_size >= inner.max_size {
                    let max_files = inner.max_files;
                    let base_path = inner.base_path.clone();

                    rotate(&mut inner)?;

                    // 释放锁后清理旧存档（非关键路径，避免阻塞其他写入）
                    drop(inner);

                    if max_files > 0 {
                        prune_old_files(&base_path, max_files);
                    }
                }

                Ok(n)
            }

            fn flush(&mut self) -> io::Result<()> {
                let mut inner = match self.inner.lock() {
                    Ok(guard) => guard,
                    Err(e) => e.into_inner(),
                };
                if let Some(file) = inner.current_file.as_mut() {
                    file.flush()
                } else {
                    Ok(())
                }
            }
        }
    };
}

impl_write_for!(RollingWriter);
impl_write_for!(&RollingWriter);

/// `RollingWriter` 的构建器，用于配置日志文件路径、最大大小和最大存档数量
pub struct RollingWriterBuilder {
    path: PathBuf,
    max_size: u64,
    max_files: usize,
}

impl RollingWriterBuilder {
    /// 创建构建器，指定日志文件路径
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        RollingWriterBuilder {
            path: path.as_ref().to_path_buf(),
            max_size: MAX_LOG_SIZE_BYTES,
            max_files: MAX_LOG_FILES,
        }
    }

    /// 设置单文件最大大小（字节，默认 10 MB）
    pub fn max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size;
        self
    }

    /// 设置最大存档文件数量（默认 10）
    pub fn max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    /// 构建并返回 `RollingWriter` 实例，同时创建或打开日志文件
    pub fn build(self) -> io::Result<RollingWriter> {
        let file = open_log_file(&self.path)?;
        // 获取已有文件大小（追加模式下文件可能已有内容）
        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(RollingWriter {
            inner: Mutex::new(RollingWriterInner {
                base_path: self.path,
                current_file: Some(file),
                current_size,
                max_size: self.max_size,
                max_files: self.max_files,
            }),
        })
    }
}

/// 打开或创建日志文件，以追加模式写入
fn open_log_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// 清理过期的存档日志文件，仅保留最近 max_files 个（含当前活动文件）
fn prune_old_files(base_path: &Path, max_files: usize) {
    let file_name = match base_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => return,
    };

    // 提取文件名 stem（如 proxy），用于匹配存档文件
    let stem = Path::new(&file_name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&file_name);

    let dir = base_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(dir) => dir.filter_map(|e| e.ok()).collect(),
        Err(_) => Vec::new(),
    };

    // 匹配存档文件：以 "{stem}." 开头（如 proxy.20260814_153045.log），且排除当前活动日志文件
    entries.retain(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.starts_with(&format!("{}.", stem)) && name != file_name
    });

    // 按修改时间倒序排列（最新的在前），优先删除最早的存档
    entries.sort_by(|a, b| {
        let a_mtime = a.metadata().and_then(|m| m.modified()).ok();
        let b_mtime = b.metadata().and_then(|m| m.modified()).ok();
        b_mtime.cmp(&a_mtime)
    });

    // 删除超出保留数量的旧存档（max_files 包含当前活动文件，所以存档保留 max_files - 1 个）
    for entry in entries.into_iter().skip(max_files.saturating_sub(1)) {
        let _ = fs::remove_file(entry.path());
    }
}

/// 初始化日志系统，配置日志级别和输出目标
///
/// 当指定了日志文件路径时，使用 `RollingWriter` 实现按文件大小自动滚动；
/// 否则日志输出到标准输出。
pub fn setup_logging(log_file: &Option<PathBuf>, log_level: &LogLevel) -> Result<()> {
    let level = match log_level {
        LogLevel::Trace => LevelFilter::Trace,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Error => LevelFilter::Error,
    };

    let mut builder = Builder::new();
    builder.filter_level(level);
    builder.format(move |buf, record| {
        let (year, month, day, hours, minutes, seconds) = get_local_datetime();

        writeln!(
            buf,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}: {}",
            year,
            month,
            day,
            hours,
            minutes,
            seconds,
            record.level(),
            record.args()
        )
    });

    if let Some(path) = log_file {
        let writer = RollingWriter::builder(path)
            .max_size(MAX_LOG_SIZE_BYTES)
            .max_files(MAX_LOG_FILES)
            .build()?;
        builder.target(env_logger::Target::Pipe(Box::new(writer)));
    }

    builder.init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 本地时间换算不得让时钟走偏
    ///
    /// 这条测试固定时区换算的关键不变量：时区偏移只能
    /// "平移显示用的墙上时间"，不能改变时间点本身。若偏移被重复施加（或符号搞反），
    /// 会立刻偏离数小时。
    #[test]
    fn test_local_time_tracks_system_clock() {
        let sys = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as i64;
        let local = now_local().unix_timestamp();
        assert!(
            (sys - local).abs() <= 5,
            "本地时间与系统时钟偏差过大：system={sys} local={local}"
        );
    }

    /// 存档文件名后缀必须是 `YYYYMMDD_HHMMSS`（日志滚动的文件名契约）
    #[test]
    fn test_timestamp_suffix_shape() {
        let ts = get_timestamp_suffix();
        assert_eq!(ts.len(), 15, "后缀长度应为 15，实际 {ts:?}");
        assert_eq!(ts.as_bytes()[8], b'_', "第 9 个字符应为下划线，实际 {ts:?}");
        assert_eq!(
            ts.chars().filter(|c| c.is_ascii_digit()).count(),
            14,
            "应含 14 位数字，实际 {ts:?}"
        );
    }

    #[test]
    fn test_size_rotation_triggers() {
        let tmp_dir = std::env::temp_dir().join("test_log_size_rotation");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let log_path = tmp_dir.join("test.log");

        // 设置 100 字节就滚动
        let writer = RollingWriter::builder(&log_path)
            .max_size(100)
            .max_files(3)
            .build()
            .unwrap();

        // 写入 150 字节，应触发滚动
        let data = "x".repeat(150);
        {
            let mut w = &writer;
            w.write_all(data.as_bytes()).unwrap();
            w.flush().unwrap();
        }

        // 当前文件应该已重置（大小 < 100）
        let current_size = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
        assert!(
            current_size < 100,
            "current file should be small after rotation, got {} bytes",
            current_size
        );

        // 应该存在存档文件
        let archives: Vec<_> = std::fs::read_dir(&tmp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("test.") && name != "test.log"
            })
            .collect();
        assert!(
            !archives.is_empty(),
            "at least one archive file should exist"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_prune_keeps_max_files() {
        let tmp_dir = std::env::temp_dir().join("test_log_prune");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let log_path = tmp_dir.join("app.log");

        // 设置 50 字节就滚动，最多 3 个文件
        let writer = RollingWriter::builder(&log_path)
            .max_size(50)
            .max_files(3)
            .build()
            .unwrap();

        // 反复写入，触发多次滚动（无需等待，unique_rotated_path 自动处理同名）
        for _ in 0..10 {
            let data = "y".repeat(60);
            let mut w = &writer;
            w.write_all(data.as_bytes()).unwrap();
            w.flush().unwrap();
        }

        // 统计文件数量（当前 + 存档）
        let all_files: Vec<_> = std::fs::read_dir(&tmp_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("app.") || name == "app.log"
            })
            .collect();

        assert!(
            all_files.len() <= 3,
            "should have at most 3 files, got {}",
            all_files.len()
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_existing_file_size_tracked() {
        let tmp_dir = std::env::temp_dir().join("test_log_existing_size");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).unwrap();

        let log_path = tmp_dir.join("existing.log");

        // 先写入一些数据
        std::fs::write(&log_path, "existing content").unwrap();

        // 打开 writer，设置阈值为 100 字节
        let writer = RollingWriter::builder(&log_path)
            .max_size(100)
            .max_files(3)
            .build()
            .unwrap();

        // 追加少量数据（不超过阈值），不应触发滚动
        let mut w = &writer;
        w.write_all(b" + more").unwrap();
        w.flush().unwrap();

        // 文件应仍为原始名（未滚动）
        assert!(log_path.exists(), "current log file should still exist");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
