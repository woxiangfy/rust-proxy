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

fn get_current_date_str() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days_since_epoch = now / (24 * 60 * 60);
    format!("{}", days_since_epoch)
}

fn next_local_midnight() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds_since_midnight = now % (24 * 60 * 60);
    now + (24 * 60 * 60 - seconds_since_midnight)
}

struct RollingWriterInner {
    base_path: PathBuf,
    current_file: Option<File>,
    current_size: u64,
    next_rotation: u64,
    max_files: usize,
}

pub struct RollingWriter {
    inner: Mutex<RollingWriterInner>,
}

impl RollingWriter {
    pub fn builder<P: AsRef<Path>>(path: P) -> RollingWriterBuilder {
        RollingWriterBuilder::new(path)
    }

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
        let _ = inner.current_file.take();
        drop(inner);

        let date = get_current_date_str();
        let file_name = base_path
            .file_name()
            .expect("log path must have a file name")
            .to_string_lossy();
        let rotated = Self::unique_rotated_path(&base_path, &file_name, &date);

        if let Err(e) = fs::rename(&base_path, &rotated) {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e);
            }
        }

        let new_file = open_log_file(&base_path)?;

        {
            let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
            inner.current_file = Some(new_file);
            inner.current_size = 0;
            inner.next_rotation = next_local_midnight();
        }

        if max_files > 0 {
            prune_old_files(&base_path, max_files);
        }

        Ok(())
    }

    fn unique_rotated_path(base_path: &Path, file_name: &str, date: &str) -> PathBuf {
        let dir = base_path
            .parent()
            .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
            .unwrap_or_else(|| Path::new("."));
        let candidate = dir.join(format!("{}.{}", file_name, date));
        if !candidate.exists() {
            return candidate;
        }
        for i in 1.. {
            let candidate = dir.join(format!("{}.{}.{}", file_name, date, i));
            if !candidate.exists() {
                return candidate;
            }
        }
        unreachable!()
    }
}

impl Write for RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_rotation()?;
        let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
        let file = inner
            .current_file
            .as_mut()
            .expect("current log file is closed");
        let written = file.write(buf)?;
        inner.current_size += written as u64;
        Ok(written)
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

impl Write for &RollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_rotation()?;
        let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
        let file = inner
            .current_file
            .as_mut()
            .expect("current log file is closed");
        let written = file.write(buf)?;
        inner.current_size += written as u64;
        Ok(written)
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

pub struct RollingWriterBuilder {
    path: PathBuf,
    max_files: usize,
}

impl RollingWriterBuilder {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        RollingWriterBuilder {
            path: path.as_ref().to_path_buf(),
            max_files: MAX_LOG_FILES,
        }
    }

    pub fn max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    pub fn build(self) -> io::Result<RollingWriter> {
        let file = open_log_file(&self.path)?;
        Ok(RollingWriter {
            inner: Mutex::new(RollingWriterInner {
                base_path: self.path,
                current_file: Some(file),
                current_size: 0,
                next_rotation: next_local_midnight(),
                max_files: self.max_files,
            }),
        })
    }
}

fn open_log_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

fn prune_old_files(base_path: &Path, max_files: usize) {
    let file_name = match base_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => return,
    };

    let dir = base_path
        .parent()
        .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
        .unwrap_or_else(|| Path::new("."));

    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(dir) => dir.filter_map(|e| e.ok()).collect(),
        Err(_) => Vec::new(),
    };
    
    entries.retain(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.starts_with(&file_name) && name != file_name
    });

    entries.sort_by_key(|e| e.path());
    entries.reverse();

    for entry in entries.into_iter().skip(max_files) {
        let _ = fs::remove_file(entry.path());
    }
}

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
    let tz_offset = get_local_offset_seconds();
    builder.format(move |buf, record| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as i64 + tz_offset;
        let date = ((secs / 86400) as u64) + 2440588;
        let seconds_in_day = (secs.rem_euclid(86400)) as u64;
        let hours = seconds_in_day / 3600;
        let minutes = (seconds_in_day % 3600) / 60;
        let seconds = seconds_in_day % 60;
        
        writeln!(
            buf,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {} {}: {}",
            julian_to_year(date),
            julian_to_month(date),
            julian_to_day(date),
            hours,
            minutes,
            seconds,
            record.level(),
            record.target(),
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

fn julian_to_year(julian: u64) -> u64 {
    let a = julian as i64 + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    100 * b as u64 + d as u64 - 4800 + (m / 10) as u64
}

fn julian_to_month(julian: u64) -> u64 {
    let a = julian as i64 + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    (m + 3 - 12 * (m / 10)) as u64
}

fn julian_to_day(julian: u64) -> u64 {
    let a = julian as i64 + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    (e - (153 * m + 2) / 5 + 1) as u64
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
    use std::ffi::CStr;

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
