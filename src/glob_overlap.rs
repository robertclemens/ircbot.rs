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
}
