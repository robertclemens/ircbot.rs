//! log_message(): the per-level in-memory rings that `getlog` reads, and the
//! size-capped LOGFILE.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::consts::*;
use crate::cstr::trunc;
use crate::state::Isupport;
use zeroize::Zeroizing;

pub struct LogRing {
    pub entries: Vec<String>,
    pub idx: usize,
}

pub struct Logger {
    /// Bitmask of L_* levels written to LOGFILE (the config's l| line).
    pub level: u32,
    /// LOGFILE cap in bytes (the config's L| line, else BOT_LOG_FILE_SIZE).
    pub max_size: u64,
    rings: RefCell<Vec<LogRing>>,
    /// LOGFILE, kept open across lines, with the (dev, ino) it was opened as.
    file: RefCell<Option<(File, u64, u64)>>,
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

/// Callers' trailing newlines are dropped, and any control byte left is
/// logged data, not layout: shown as '?', a CR/LF cannot forge a second entry
/// or split getlog's PRIVMSG.
fn clean(msg: &str) -> String {
    trunc(msg, MAX_LOG_LINE_LEN - 40)
        .trim_end_matches(['\n', '\r'])
        .chars()
        .map(|c| {
            if (c as u32) < 0x20 || c as u32 == 0x7f {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Channel keys in a raw IRC line, masked: the key list of a JOIN and the
/// argument of each k in a MODE or a 324 (RPL_CHANNELMODEIS), found with the
/// server's ISUPPORT argument table so "+lk 20 key" masks the right one.
/// Everything else is copied as is.
pub fn mask_keys(isup: &Isupport, line: &str) -> String {
    mask_line(isup, line, 0)
}

/// Where a PRIVMSG / NOTICE text quotes a raw log line (a getlog raw
/// reply): the byte just past its "[RAW_SEND] " / "[RAW_RECV] " tag.
fn raw_quote(line: &str) -> Option<usize> {
    let a = line.find("[RAW_SEND] ");
    let b = line.find("[RAW_RECV] ");
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
    .map(|q| q + 11)
}

/// mask_keys, plus the same in a raw line a PRIVMSG / NOTICE quotes (the
/// bot's own getlog raw reply, which would otherwise write the ring's keys
/// into the file).
fn mask_line(isup: &Isupport, line: &str, depth: u32) -> String {
    let tok: Vec<&str> = line.split(' ').filter(|s| !s.is_empty()).take(64).collect();
    let n = tok.len();
    let mut mask = vec![false; n];
    let i = usize::from(n > 0 && tok[0].starts_with(':'));
    if i < n
        && depth < 3
        && (tok[i].eq_ignore_ascii_case("PRIVMSG") || tok[i].eq_ignore_ascii_case("NOTICE"))
        && let Some(q) = raw_quote(line)
    {
        return format!("{}{}", &line[..q], mask_line(isup, &line[q..], depth + 1));
    }
    if i < n && tok[i].eq_ignore_ascii_case("JOIN") {
        if i + 2 < n {
            mask[i + 2] = true;
        }
    } else if i < n && (tok[i].eq_ignore_ascii_case("MODE") || tok[i] == "324") {
        let m = i + if tok[i] == "324" { 3 } else { 2 };
        let mut a = m + 1;
        let mut adding = true;
        for &c in tok.get(m).map_or(&b""[..], |s| s.as_bytes()) {
            if a >= n {
                break;
            }
            match c {
                b'+' | b'-' => adding = c == b'+',
                b':' => {}
                _ if isup.mode_has_arg(c, adding) => {
                    if c == b'k' {
                        mask[a] = true;
                    }
                    a += 1;
                }
                _ => {}
            }
        }
    }
    let out: Vec<String> = tok
        .iter()
        .zip(&mask)
        .map(|(s, &m)| {
            if !m {
                return (*s).to_string();
            }
            // one **** per comma-separated key; a trailing-parameter colon stays
            let (colon, keys) = s.strip_prefix(':').map_or(("", *s), |k| (":", k));
            let keys: Vec<&str> = keys
                .split(',')
                .map(|k| if k.is_empty() { "" } else { "****" })
                .collect();
            format!("{colon}{}", keys.join(","))
        })
        .collect();
    out.join(" ")
}

fn local_time_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

impl Logger {
    pub fn new(level: u32) -> Self {
        let rings = (0..NUM_LOG_LEVELS)
            .map(|_| LogRing {
                entries: vec![String::new(); LOG_BUFFER_LINES],
                idx: 0,
            })
            .collect();
        Logger {
            level,
            max_size: BOT_LOG_FILE_SIZE,
            rings: RefCell::new(rings),
            file: RefCell::new(None),
        }
    }

    /// Record one line.  Callers' trailing newlines are dropped, and any
    /// control byte left is logged data, not layout: shown as '?', a CR/LF
    /// cannot forge a second entry or split getlog's PRIVMSG.
    pub fn log(&self, flag: u32, msg: &str) {
        self.write(flag, msg, None);
    }

    /// A raw IRC line ("[RAW_SEND] ", "[RAW_RECV] "): the ring keeps it as
    /// sent, for an admin's getlog; LOGFILE gets its channel keys masked
    /// (L1b).
    pub fn log_raw(&self, isup: &Isupport, tag: &str, line: &str) {
        let ring = Zeroizing::new(format!("{tag}{line}"));
        if self.level & L_RAW == 0 {
            // ring only: nothing reaches the file
            self.write(L_RAW, &ring, None);
            return;
        }
        let masked = Zeroizing::new(format!("{tag}{}", mask_keys(isup, &clean(line))));
        self.write(L_RAW, &ring, Some(&masked));
    }

    /// One entry: `msg` goes to the in-memory ring (getlog), `file` -- a
    /// masked copy of it, else `msg` itself -- to LOGFILE.
    fn write(&self, flag: u32, msg: &str, file: Option<&str>) {
        let time_buf = local_time_str();
        let full = format!("[{time_buf}] {}", clean(msg));
        let full = trunc(&full, MAX_LOG_LINE_LEN).to_string();

        if let Some(i) = level_index(flag)
            && let Ok(mut rings) = self.rings.try_borrow_mut()
        {
            let r = &mut rings[i];
            let at = r.idx;
            r.entries[at] = full.clone();
            r.idx = (at + 1) % LOG_BUFFER_LINES;
        }

        if self.level & flag == 0 {
            return;
        }

        // LOGFILE stays open between lines (it was opened and closed for
        // every one).  The stat each line needs for the size cap also says
        // whether the open file is still LOGFILE -- removed, replaced, or a
        // chdir into the instance dir since -- and if not it is opened again.
        let Ok(mut slot) = self.file.try_borrow_mut() else {
            return;
        };
        let md = std::fs::metadata(LOGFILE).ok();
        if slot
            .as_ref()
            .is_some_and(|(_, d, i)| md.as_ref().is_none_or(|m| m.dev() != *d || m.ino() != *i))
        {
            *slot = None;
        }
        let mut size = md.map(|m| m.len());
        if slot.is_none() {
            let opened = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(LOGFILE)
                .and_then(|f| f.metadata().map(|m| (f, m)));
            match opened {
                Ok((f, m)) => {
                    size = Some(m.len());
                    *slot = Some((f, m.dev(), m.ino()));
                }
                Err(e) => {
                    eprintln!("Failed to open log file: {e}");
                    return;
                }
            }
        }
        let Some((f, _, _)) = slot.as_mut() else {
            return;
        };
        // Past the size cap the file is truncated rather than left to grow,
        // and this line is then written after the truncation notice (O_APPEND
        // puts both at the new end).
        if size.is_some_and(|n| n >= self.max_size) && f.set_len(0).is_ok() {
            let _ = writeln!(f, "[{time_buf}] Log file truncated (size limit reached)");
        }
        match file {
            Some(m) => {
                let line = format!("[{time_buf}] {}", clean(m));
                let _ = writeln!(f, "{}", trunc(&line, MAX_LOG_LINE_LEN));
            }
            None => {
                let _ = writeln!(f, "{full}");
            }
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
        if let Ok(mut f) = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(LOGFILE)
        {
            let _ = writeln!(f, "[FATAL] {} - bot terminating.", trunc(&what, 400));
        }
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keys_in_raw_lines() {
        let is = Isupport::default();
        let m = |l: &str| mask_keys(&is, l);
        assert_eq!(m("JOIN #a,#b k1,k2"), "JOIN #a,#b ****,****");
        assert_eq!(m("JOIN #a"), "JOIN #a");
        assert_eq!(m(":srv MODE #a +lk 20 key"), ":srv MODE #a +lk 20 ****");
        assert_eq!(
            m(":n!u@h MODE #a +o-k bot :key"),
            ":n!u@h MODE #a +o-k bot :****"
        );
        assert_eq!(
            m(":srv 324 me #a +nkl key 20"),
            ":srv 324 me #a +nkl **** 20"
        );
        assert_eq!(m(":srv MODE #a +b x!*@*"), ":srv MODE #a +b x!*@*");
        assert_eq!(m("PRIVMSG #a :JOIN #b key"), "PRIVMSG #a :JOIN #b key");
        assert_eq!(
            m("PRIVMSG adm :[2026-10-26 16:38:13] [RAW_SEND] JOIN #b k1"),
            "PRIVMSG adm :[2026-10-26 16:38:13] [RAW_SEND] JOIN #b ****"
        );
        assert_eq!(
            m("NOTICE adm :[t] [RAW_RECV] :srv 324 me #b +k key"),
            "NOTICE adm :[t] [RAW_RECV] :srv 324 me #b +k ****"
        );
    }
}
