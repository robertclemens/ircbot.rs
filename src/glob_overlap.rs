//! Glob pattern overlap (glob_overlap.c).  The hub carries an identical
//! helper.

/// Longest pattern [`glob_overlap`] will analyse; longer input is reported
/// as overlapping (fail closed: callers use it to refuse unsafe bans).
pub const GLOB_OVERLAP_MAX: usize = 256;

/// True when at least one string is matched by BOTH glob patterns, where '*'
/// matches any run (including none) and '?' any one character.  Letters
/// compare ASCII case-insensitively.  Pure; O(len(a)*len(b)).
///
/// ov(i,j): is there a string matched by a[i..] and by b[j..]?
///   both ended                 -> yes
///   a[i] == '*'                -> ov(i+1,j)  (star empty)
///                                 or, if b has a symbol left, ov(i,j+1)
///                                 (star swallows that symbol of b)
///   b[j] == '*'                -> symmetric
///   one ended, other not '*'   -> no
///   else                       -> symbols compatible and ov(i+1,j+1)
/// Filled bottom-up in two rolling rows.
pub fn glob_overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (la, lb) = (a.len(), b.len());
    if la > GLOB_OVERLAP_MAX || lb > GLOB_OVERLAP_MAX {
        return true;
    }
    let mut next = [0u8; GLOB_OVERLAP_MAX + 2]; // row i+1
    let mut cur = [0u8; GLOB_OVERLAP_MAX + 2]; // row i

    // Row i = la: a has ended.
    next[lb] = 1;
    for j in (0..lb).rev() {
        next[j] = if b[j] == b'*' { next[j + 1] } else { 0 };
    }

    for i in (0..la).rev() {
        cur[lb] = if a[i] == b'*' { next[lb] } else { 0 }; // b ended
        for j in (0..lb).rev() {
            cur[j] = if a[i] == b'*' || b[j] == b'*' {
                next[j] | cur[j + 1]
            } else if a[i] == b'?' || b[j] == b'?' || a[i].eq_ignore_ascii_case(&b[j]) {
                next[j + 1]
            } else {
                0
            };
        }
        std::mem::swap(&mut next, &mut cur);
    }
    next[0] != 0
}

/// [`glob_overlap`] for nick!user@host ban masks: each pattern is split at
/// its first '!' and the first '@' after it, and the masks overlap only when
/// the nick, user and host parts all do.  A plain [`glob_overlap`] lets a '*'
/// run across '!' and '@' (so "*!*@aol.com" and "*!*@149.76.*.*" share
/// "a!b@149.76.x!y@aol.com"), which no real hostmask can be.  A pattern not
/// of that shape falls back to [`glob_overlap`] of the whole string.
/// Host parts are typed first: one with a ':' (IPv6), or of only digits, '.',
/// '*' and '?' with at least one digit (IPv4), is an address; one with any
/// other symbol (a letter, '-', '/') is a name; an address pattern never
/// overlaps a name pattern ("*aol.com" vs "149.76.*.*"), since no admin
/// writes a name host as bare digits.  Wildcards-only ("*") overlap both.
pub fn hostmask_overlap(a: &str, b: &str) -> bool {
    fn split(m: &str) -> Option<(&str, &str, &str)> {
        let (nick, rest) = m.split_once('!')?;
        let (user, host) = rest.split_once('@')?;
        Some((nick, user, host))
    }
    /// 'i' address, 'n' name, 'a' wildcards only (either).
    fn host_kind(h: &str) -> u8 {
        if h.contains(':') {
            return b'i';
        }
        let other = h
            .bytes()
            .any(|c| !c.is_ascii_digit() && !b".*?".contains(&c));
        if other {
            b'n'
        } else if h.bytes().any(|c| c.is_ascii_digit()) {
            b'i'
        } else {
            b'a'
        }
    }
    match (split(a), split(b)) {
        (Some((an, au, ah)), Some((bn, bu, bh)))
            if a.len() <= GLOB_OVERLAP_MAX && b.len() <= GLOB_OVERLAP_MAX =>
        {
            let (ka, kb) = (host_kind(ah), host_kind(bh));
            (ka == b'a' || kb == b'a' || ka == kb)
                && glob_overlap(an, bn)
                && glob_overlap(au, bu)
                && glob_overlap(ah, bh)
        }
        _ => glob_overlap(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::glob_overlap as ov;

    #[test]
    fn overlap() {
        assert!(ov("*!*@*", "nick!u@h"));
        assert!(ov("a*", "*b"));
        assert!(ov("n?ck!*@*.example.com", "N*!u@h.example.com"));
        assert!(!ov("nick!*@a", "nick!*@b"));
        assert!(!ov("abc", "abd"));
        assert!(ov("", "*"));
        assert!(!ov("", "a"));
        assert!(ov(&"a".repeat(300), "b"));
    }

    #[test]
    fn hostmask() {
        use super::hostmask_overlap as hm;
        assert!(!hm("*!*@aol.com", "*!*@149.76.*.*"));
        assert!(!hm("aol*!*aol@aol.com", "*!*@149.76.*.*"));
        assert!(hm("*!*@*.aol.com", "nick!u@h.aol.com"));
        assert!(hm("*!*@*", "*!*@149.76.*.*"));
        assert!(hm("*@aol.com", "*!*@aol.com"));
        assert!(!hm("a!*@*", "b!*@*"));
        assert!(!hm("*!*@*aol.com", "*!*@149.76.*.*"));
        assert!(!hm("aol*!*aol@*aol.com", "*!*@149.76.*.*"));
        assert!(hm("*!*@*aol.com", "*!*@149.76.*.aol.com"));
        assert!(hm("*!*@149.*", "*!*@149.76.1.2"));
        assert!(hm("*!*@*", "*!*@2001:db8::*"));
        assert!(!hm("*!*@*.example", "*!*@2001:db8::*"));
        assert!(!hm("*!*@user/*", "*!*@1.2.*"));
    }
}
