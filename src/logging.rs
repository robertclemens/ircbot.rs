//! log_message(): the per-level in-memory rings that `getlog` reads, and the
//! size-capped LOGFILE.

use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::consts::*;
use crate::cstr::trunc;

pub struct LogRing {
    pub entries: Vec<String>,
    pub idx: usize,
}

pub struct Logger {
    /// Bitmask of L_* levels written to LOGFILE (the config's l| line).
    pub level: u32,
    rings: RefCell<Vec<LogRing>>,
}

/// Ring index for a level flag (get_log_index).
pub fn level_index(flag: u32) -> Option<usize> {
    match flag {
        L_MSG => Some(0),
        L_CTCP => Some(1),
        L_INFO => Some(2),
        L_CMD => Some(3),
        L_RAW => Some(4),
        L_DEBUG => Some(5),
        _ => None,
    }
}

fn local_time_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

impl Logger {
    pub fn new(level: u32) -> Self {
        let rings = (0..NUM_LOG_LEVELS)
            .map(|_| LogRing { entries: vec![String::new(); LOG_BUFFER_LINES], idx: 0 })
            .collect();
        Logger { level, rings: RefCell::new(rings) }
    }

    /// Record one line.  Callers' trailing newlines are dropped, and any
    /// control byte left is logged data, not layout: shown as '?', a CR/LF
    /// cannot forge a second entry or split getlog's PRIVMSG.
    pub fn log(&self, flag: u32, msg: &str) {
        let time_buf = local_time_str();
        let base = trunc(msg, MAX_LOG_LINE_LEN - 40);
        let base = base.trim_end_matches(['\n', '\r']);
        let clean: String = base
            .chars()
            .map(|c| if (c as u32) < 0x20 || c as u32 == 0x7f { '?' } else { c })
            .collect();
        let full = format!("[{time_buf}] {clean}");
        let full = trunc(&full, MAX_LOG_LINE_LEN).to_string();

        if let Some(i) = level_index(flag) {
            if let Ok(mut rings) = self.rings.try_borrow_mut() {
                let r = &mut rings[i];
                let at = r.idx;
                r.entries[at] = full.clone();
                r.idx = (at + 1) % LOG_BUFFER_LINES;
            }
        }

        if self.level & flag == 0 {
            return;
        }

        // Past the size cap the file is truncated rather than left to grow.
        if let Ok(md) = std::fs::metadata(LOGFILE) {
            if md.len() >= BOT_LOG_FILE_SIZE {
                if let Ok(mut f) = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(LOGFILE) {
                    let _ = writeln!(f, "[{time_buf}] Log file truncated (size limit reached)");
                }
            }
        }
        match OpenOptions::new().append(true).create(true).mode(0o600).open(LOGFILE) {
            Ok(mut f) => {
                let _ = writeln!(f, "{full}");
            }
            Err(e) => eprintln!("Failed to open log file: {e}"),
        }
    }

    /// The non-empty entries of one ring, oldest first.
    pub fn ring_entries(&self, index: usize) -> Vec<String> {
        let rings = self.rings.borrow();
        let r = &rings[index];
        (0..LOG_BUFFER_LINES)
            .map(|i| &r.entries[(r.idx + i) % LOG_BUFFER_LINES])
            .filter(|e| !e.is_empty())
            .cloned()
            .collect()
    }
}

/// `logm!(state, L_INFO, "fmt", args...)` -- log_message() with format!.
#[macro_export]
macro_rules! logm {
    ($st:expr, $flag:expr, $($arg:tt)*) => {
        $st.log.log($flag, &format!($($arg)*))
    };
}

/// Record a fatal panic in LOGFILE before the process goes down, the job
/// bot.c's fatal-signal handler did for SIGSEGV and friends (safe Rust does
/// not segfault; a panic is its crash).
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let what = info.to_string().replace(['\r', '\n'], " ");
        if let Ok(mut f) = OpenOptions::new().append(true).create(true).mode(0o600).open(LOGFILE) {
            let _ = writeln!(f, "[FATAL] {} - bot terminating.", trunc(&what, 400));
        }
        prev(info);
    }));
}
