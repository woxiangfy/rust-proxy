//! Logging module for initializing tracing logger with rotation support

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::Result;
use chrono::{Days, Local, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, fmt::format::Writer, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::LogLevel;

const MAX_LOG_FILES: usize = 10;

struct CustomFormatEvent;

impl<S, N> fmt::FormatEvent<S, N> for CustomFormatEvent
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'writer> fmt::FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let now = SystemTime::now();
        let datetime: chrono::DateTime<chrono::Local> = now.into();
        write!(writer, "{} ", datetime.format("%Y-%m-%d %H:%M:%S"))?;
        
        write!(writer, "{} ", event.metadata().level())?;
        
        write!(writer, "{}: ", event.metadata().target())?;
        
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

pub fn setup_logging(log_file: &Option<PathBuf>, log_level: &LogLevel) -> Result<Option<WorkerGuard>> {
    let level = log_level.to_tracing_level();
    let filter = EnvFilter::from_default_env()
        .add_directive(level.into());

    if let Some(path) = log_file {
        let writer = RollingWriter::builder(path)
            .max_files(MAX_LOG_FILES)
            .build()?;

        let (non_blocking_writer, guard) = tracing_appender::non_blocking(writer);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_writer(non_blocking_writer)
                    .with_ansi(false)
                    .event_format(CustomFormatEvent)
            )
            .init();

        Ok(Some(guard))
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .event_format(CustomFormatEvent)
            )
            .init();

        Ok(None)
    }
}

struct RollingWriterInner {
    base_path: PathBuf,
    current_file: Option<File>,
    current_size: u64,
    next_rotation: chrono::DateTime<Local>,
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
        let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
        if chrono::Local::now() < inner.next_rotation {
            return Ok(());
        }

        let base_path = inner.base_path.clone();
        let max_files = inner.max_files;
        let _ = inner.current_file.take();
        drop(inner);

        let date = chrono::Local::now().format("%Y-%m-%d").to_string();
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
        let next_rotation = next_local_midnight();

        {
            let mut inner = self.inner.lock().expect("rolling writer mutex poisoned");
            inner.current_file = Some(new_file);
            inner.current_size = 0;
            inner.next_rotation = next_rotation;
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

impl std::fmt::Debug for RollingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("rolling writer mutex poisoned");
        f.debug_struct("RollingWriter")
            .field("path", &inner.base_path)
            .finish_non_exhaustive()
    }
}

pub struct RollingWriterBuilder {
    path: PathBuf,
    max_files: usize,
}

impl RollingWriterBuilder {
    fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            max_files: 0,
        }
    }

    pub fn max_files(mut self, max: usize) -> Self {
        self.max_files = max;
        self
    }

    pub fn build(self) -> io::Result<RollingWriter> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = open_log_file(&self.path)?;
        let current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let next_rotation = next_local_midnight();

        Ok(RollingWriter {
            inner: Mutex::new(RollingWriterInner {
                base_path: self.path,
                current_file: Some(file),
                current_size,
                next_rotation,
                max_files: self.max_files,
            }),
        })
    }
}

fn open_log_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn next_local_midnight() -> chrono::DateTime<Local> {
    let now = chrono::Local::now();
    let tomorrow = now.date_naive() + Days::new(1);
    let midnight = NaiveDateTime::new(tomorrow, NaiveTime::from_hms_opt(0, 0, 0).unwrap());
    match Local.from_local_datetime(&midnight) {
        LocalResult::Single(dt) => dt,
        _ => now + chrono::Duration::days(1),
    }
}

fn prune_old_files(base_path: &Path, max_files: usize) {
    let dir = base_path
        .parent()
        .and_then(|p| if p.as_os_str().is_empty() { None } else { Some(p) })
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let base_name = match base_path.file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => return,
    };

    let prefix = format!("{}.", base_name);

    let mut archives: Vec<(PathBuf, NaiveDate)> = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(&prefix) {
            continue;
        }

        let suffix = &name[prefix.len()..];
        let date_part = suffix.split('.').next().unwrap_or(suffix);
        if let Ok(date) = NaiveDate::parse_from_str(date_part, "%Y-%m-%d") {
            archives.push((entry.path(), date));
        }
    }

    if archives.len() <= max_files {
        return;
    }

    archives.sort_by(|a, b| b.1.cmp(&a.1));

    for (path, _) in archives.iter().skip(max_files) {
        let _ = fs::remove_file(path);
    }
}
