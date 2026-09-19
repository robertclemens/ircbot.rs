//! Fixed-size secret buffers: heap-pinned, mlock'd where the OS allows it,
//! and wiped on drop.
//!
//! The C bot mlock'd its whole state and cleansed the key material by hand.
//! Here each long-lived secret (identity key, startup password, hub session
//! key) sits in its own [`Locked`] buffer: the heap address never moves, so
//! the lock covers it for its whole life and no stale copy is left behind by
//! a move.  Locking is best-effort (RLIMIT_MEMLOCK); root can still read
//! process memory -- see docs/admin_cmd_encryption.md.

use zeroize::Zeroize;

pub struct Locked<const N: usize> {
    // Declared first so it drops first: unlock, then the wiped buffer is freed.
    _guard: Option<region::LockGuard>,
    buf: Box<[u8; N]>,
}

impl<const N: usize> Locked<N> {
    pub fn new() -> Self {
        let buf = Box::new([0u8; N]);
        let guard = region::lock(buf.as_ptr(), N).ok();
        Locked { _guard: guard, buf }
    }

    pub fn is_locked(&self) -> bool {
        self._guard.is_some()
    }

    pub fn get(&self) -> &[u8; N] {
        &self.buf
    }

    pub fn set(&mut self, src: &[u8; N]) {
        self.buf.copy_from_slice(src);
    }

    pub fn wipe(&mut self) {
        self.buf.zeroize();
    }

    pub fn is_zero(&self) -> bool {
        self.buf.iter().all(|&b| b == 0)
    }

    /// NUL-terminated text stored in the buffer (the startup password).
    pub fn set_str(&mut self, s: &str) {
        self.wipe();
        let n = s.len().min(N.saturating_sub(1));
        self.buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    }

    pub fn get_str(&self) -> zeroize::Zeroizing<String> {
        let n = self.buf.iter().position(|&b| b == 0).unwrap_or(N);
        zeroize::Zeroizing::new(String::from_utf8_lossy(&self.buf[..n]).into_owned())
    }
}

impl<const N: usize> Default for Locked<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for Locked<N> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}
