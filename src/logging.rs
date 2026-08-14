//! Logging module for initializing logger with rotation support

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use env_logger::Builder;
use log::LevelFilter;

use crate::config::LogLevel;

/// 日志文件最大大小（10 MB），超过后自动分割
const MAX_LOG_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// 最多保留的日志文件数量（含当前活动文件）
const MAX_LOG_FILES: usize = 10;

/// 获取当前本地时间的 (年, 月, 日, 时, 分, 秒) 元组
fn get_local_datetime() -> (u64, u64, u64, u64, u64, u64) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let tz_offset = get_local_offset_seconds();
    let secs = now.as_secs() as i64 + tz_offset;
    let date = ((secs / 86400) as u64) + 2440588;
    let (year, month, day) = julian_to_ymd(date);
    let seconds_in_day = (secs.rem_euclid(86400)) as u64;
    let hours = seconds_in_day / 3600;
    let minutes = (seconds_in_day % 3600) / 60;
    let seconds = seconds_in_day % 60;
    (year, month, day, hours, minutes, seconds)
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
        .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
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
                let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");

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
                let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
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
        .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
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

/// 将儒略日转换为 (年, 月, 日) 三元组
fn julian_to_ymd(julian: u64) -> (u64, u64, u64) {
    let a = julian as i64 + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let year = 100 * b as u64 + d as u64 - 4800 + (m / 10) as u64;
    let month = (m + 3 - 12 * (m / 10)) as u64;
    let day = (e - (153 * m + 2) / 5 + 1) as u64;
    (year, month, day)
}

/// 获取本地时区偏移量（秒）
#[cfg(windows)]
fn get_local_offset_seconds() -> i64 {
    use std::mem::MaybeUninit;

    #[repr(C)]
    struct SystemTimeRaw {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }

    #[repr(C)]
    struct TimeZoneInformation {
        bias: i32,
        standard_name: [u16; 32],
        standard_date: SystemTimeRaw,
        standard_bias: i32,
        daylight_name: [u16; 32],
        daylight_date: SystemTimeRaw,
        daylight_bias: i32,
    }

    extern "system" {
        fn GetTimeZoneInformation(
            lptimezoneinformation: *mut TimeZoneInformation,
        ) -> u32;
    }

    unsafe {
        let mut tz_info: MaybeUninit<TimeZoneInformation> = MaybeUninit::uninit();
        let result = GetTimeZoneInformation(tz_info.as_mut_ptr());
        let tz_info = tz_info.assume_init();

        // bias 是 UTC 偏移量（分钟），值为正表示 UTC 之前（如 UTC+8 的 bias = -480）
        let bias = tz_info.bias;
        // 根据当前是否处于夏令时，附加额外偏移
        let additional_bias = if result == 2 {
            // TIME_ZONE_ID_DAYLIGHT
            tz_info.daylight_bias
        } else {
            // TIME_ZONE_ID_STANDARD 或 TIME_ZONE_ID_UNKNOWN
            tz_info.standard_bias
        };

        let total_bias = bias + additional_bias;
        -(total_bias as i64) * 60
    }
}

/// 获取本地时区偏移量（秒）
#[cfg(not(windows))]
fn get_local_offset_seconds() -> i64 {
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const i8,
    }

    extern "C" {
        fn time(t: *mut i64) -> i64;
        fn localtime_r(t: *const i64, result: *mut Tm) -> *mut Tm;
    }

    unsafe {
        let mut t: i64 = 0;
        time(&mut t);
        let mut tm: Tm = std::mem::zeroed();
        localtime_r(&t, &mut tm);
        tm.tm_gmtoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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
