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

/// 获取当前本地日期的字符串表示，格式为 YYYYMMDD（如 20260726）
fn get_current_date_str() -> String {
    let (year, month, day, _, _, _) = get_local_datetime();
    format!("{:04}{:02}{:02}", year, month, day)
}

/// 计算下一个本地午夜（00:00:00）的 Unix 时间戳，用于日志按天滚动
/// 基于本地时区计算，确保滚动时间与日期后缀一致
fn next_local_midnight() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tz_offset = get_local_offset_seconds();
    let local_seconds = now as i64 + tz_offset;
    let seconds_since_midnight = (local_seconds.rem_euclid(86400)) as u64;
    now + (86400 - seconds_since_midnight)
}

/// 滚动日志写入器的内部状态
struct RollingWriterInner {
    base_path: PathBuf,
    current_file: Option<File>,
    next_rotation: u64,
    max_files: usize,
}

/// 按天滚动的日志写入器，实现了 `Write` trait
///
/// 每天自动将当前日志文件重命名为带日期后缀的存档文件（如 proxy.20260726.log），
/// 并创建新的日志文件继续写入。自动清理超过 `max_files` 个的历史存档。
pub struct RollingWriter {
    inner: Mutex<RollingWriterInner>,
}

impl RollingWriter {
    /// 创建一个新的 `RollingWriterBuilder` 构建器
    pub fn builder<P: AsRef<Path>>(path: P) -> RollingWriterBuilder {
        RollingWriterBuilder::new(path)
    }

    /// 检查是否需要执行日志滚动（按天），若需要则将当前日志重命名为存档文件
    /// 整个滚动操作在锁内完成，防止并发写入时文件句柄为 None 导致 panic
    fn check_rotation(&self) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
        if now < inner.next_rotation {
            return Ok(());
        }

        let base_path = inner.base_path.clone();
        let max_files = inner.max_files;

        // 在锁内完成文件重命名和新文件创建，确保原子性
        let date = get_current_date_str();
        let file_name = base_path
            .file_name()
            .expect("log path must have a file name")
            .to_string_lossy();
        let rotated = Self::unique_rotated_path(&base_path, &file_name, &date);

        // 先关闭旧文件句柄，再重命名（Windows 上文件被占用时 rename 会失败）
        let _ = inner.current_file.take();

        if let Err(e) = fs::rename(&base_path, &rotated) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }

        let new_file = open_log_file(&base_path)?;
        inner.current_file = Some(new_file);
        inner.next_rotation = next_local_midnight();

        // 释放锁后清理旧存档（非关键路径，避免阻塞写入）
        drop(inner);

        if max_files > 0 {
            prune_old_files(&base_path, max_files);
        }

        Ok(())
    }

    /// 生成唯一的存档文件路径
    /// 格式：{stem}.{date}.{ext}（如 proxy.20260726.log）
    /// 若文件已存在，则追加序号：{stem}.{date}.{ext}.1
    fn unique_rotated_path(base_path: &Path, file_name: &str, date: &str) -> PathBuf {
        let dir = base_path
            .parent()
            .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
            .unwrap_or_else(|| Path::new("."));

        // 拆分文件名，获取 stem（如 proxy）和 extension（如 log）
        let path = Path::new(file_name);
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(file_name);
        let ext = path.extension().and_then(|e| e.to_str());

        // 组合存档文件名：stem.date.ext
        let rotated_name = match ext {
            Some(ext) => format!("{}.{}.{}", stem, date, ext),
            None => format!("{}.{}", stem, date),
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
}

macro_rules! impl_write_for {
    ($ty:ty) => {
        impl Write for $ty {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.check_rotation()?;
                let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
                let file = inner
                    .current_file
                    .as_mut()
                    .expect("current log file is closed");
                file.write(buf)
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
    }
}

impl_write_for!(RollingWriter);
impl_write_for!(&RollingWriter);

/// `RollingWriter` 的构建器，用于配置日志文件路径和最大存档数量
pub struct RollingWriterBuilder {
    path: PathBuf,
    max_files: usize,
}

impl RollingWriterBuilder {
    /// 创建构建器，指定日志文件路径
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        RollingWriterBuilder {
            path: path.as_ref().to_path_buf(),
            max_files: MAX_LOG_FILES,
        }
    }

    /// 设置最大存档文件数量（默认 10）
    pub fn max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    /// 构建并返回 `RollingWriter` 实例，同时创建或打开日志文件
    pub fn build(self) -> io::Result<RollingWriter> {
        let file = open_log_file(&self.path)?;
        Ok(RollingWriter {
            inner: Mutex::new(RollingWriterInner {
                base_path: self.path,
                current_file: Some(file),
                next_rotation: next_local_midnight(),
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

/// 清理过期的存档日志文件，仅保留最近 max_files 个
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

    // 匹配存档文件：以 "{stem}." 开头（如 proxy.20260726.log），且排除当前活动日志文件
    entries.retain(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.starts_with(&format!("{}.", stem)) && name != file_name
    });

    // 按路径排序后倒序排列，优先删除最早的存档
    entries.sort_by_key(|e| e.path());
    entries.reverse();

    // 删除超出保留数量的旧存档
    for entry in entries.into_iter().skip(max_files) {
        let _ = fs::remove_file(entry.path());
    }
}

/// 初始化日志系统，配置日志级别和输出目标
///
/// 当指定了日志文件路径时，使用 `RollingWriter` 实现按天自动滚动；
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
