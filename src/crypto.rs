//! Cryptographic primitives (crypto.c), on RustCrypto and dalek.
//!
//! Every construction here is on the wire or on disk and must stay
//! bit-for-bit compatible with irchub and the client scripts in utils/:
//!
//! * AES-256-GCM, 12-byte random IV, 16-byte tag, optional AAD.
//! * Combined identity key: Ed25519 seed (32) || X25519 private (32);
//!   public half Ed25519 (32) || X25519 (32).
//! * Sealed frame (~A2 / ~A2S / ~A2K / ~B2): eph_pub(32) || iv(12) || ct ||
//!   tag(16) with key = HKDF-SHA256(ikm, salt = eph_pub,
//!   info = label || [s_x_pub] || r_x_pub), ikm = X25519(eph, R) ||
//!   [X25519(S, R)].
//! * ~A2R reply frame: iv(12) || ct || tag(16) under a derived reply key.
//!
//! Secrets live in `Zeroizing` buffers and are wiped on drop.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use base64::{Engine, alphabet};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::consts::*;

pub type Key32 = Zeroizing<[u8; 32]>;

/// RAND_bytes: fill from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> bool {
    getrandom::fill(buf).is_ok()
}

/// A random index below `n` (n > 0); the C code's rand() % n picks.
pub fn random_index(n: usize) -> usize {
    let mut b = [0u8; 8];
    if n == 0 || !random_bytes(&mut b) {
        return 0;
    }
    (u64::from_le_bytes(b) % n as u64) as usize
}

/// Random RFC 4122 v4 UUID, lower-case hex.
pub fn gen_uuid_v4() -> Option<String> {
    let mut r = [0u8; 16];
    if !random_bytes(&mut r) {
        return None;
    }
    r[6] = (r[6] & 0x0f) | 0x40;
    r[8] = (r[8] & 0x3f) | 0x80;
    let h: Vec<String> = r.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    ))
}

/// PBKDF2-HMAC-SHA256 (PBKDF2_ITERATIONS) over a password: the config-file
/// and pass-file key.
pub fn derive_config_key(password: &[u8], salt: &[u8]) -> Key32 {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, PBKDF2_ITERATIONS, key.as_mut());
    key
}

/// The pre-PBKDF2 config key: OpenSSL EVP_BytesToKey(aes-256-gcm, sha256,
/// salt, password, 1 round), i.e. SHA-256(password || salt[0..8]).  Only used
/// to migrate an old config once.
pub fn legacy_config_key(password: &[u8], salt: &[u8]) -> Key32 {
    let mut h = Sha256::new();
    h.update(password);
    h.update(&salt[..salt.len().min(8)]);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&h.finalize());
    key
}

fn cipher(key: &[u8]) -> Option<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).ok()
}

/// AES-256-GCM with a caller-supplied IV; returns (ciphertext, tag).
pub fn gcm_encrypt_detached(
    key: &[u8],
    iv: &[u8; GCM_IV_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Option<(Vec<u8>, [u8; GCM_TAG_LEN])> {
    let c = cipher(key)?;
    let mut buf = pt.to_vec();
    let nonce = Nonce::try_from(&iv[..]).ok()?;
    let tag = c
        .encrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into())
        .ok()?;
    let mut t = [0u8; GCM_TAG_LEN];
    t.copy_from_slice(&tag);
    Some((buf, t))
}

/// Inverse of [`gcm_encrypt_detached`]; None on a bad tag (nothing is
/// returned from an unauthenticated decryption).
pub fn gcm_decrypt_detached(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if iv.len() != GCM_IV_LEN || tag.len() != GCM_TAG_LEN {
        return None;
    }
    let c = cipher(key)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    let nonce = Nonce::try_from(iv).ok()?;
    let tag = Tag::try_from(tag).ok()?;
    c.decrypt_inout_detached(&nonce, aad, buf.as_mut_slice().into(), &tag)
        .ok()?;
    Some(buf)
}

/// iv(12, random) || ct || tag(16) -- the layout of hub frames, sealed
/// frames and ~A2R replies.
pub fn gcm_seal(key: &[u8], aad: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    let mut iv = [0u8; GCM_IV_LEN];
    if !random_bytes(&mut iv) {
        return None;
    }
    let (ct, tag) = gcm_encrypt_detached(key, &iv, aad, pt)?;
    let mut out = Vec::with_capacity(GCM_IV_LEN + ct.len() + GCM_TAG_LEN);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Some(out)
}

/// Inverse of [`gcm_seal`].
pub fn gcm_open(key: &[u8], aad: &[u8], frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if frame.len() < GCM_IV_LEN + GCM_TAG_LEN {
        return None;
    }
    let (iv, rest) = frame.split_at(GCM_IV_LEN);
    let (ct, tag) = rest.split_at(rest.len() - GCM_TAG_LEN);
    gcm_decrypt_detached(key, iv, aad, ct, tag)
}

/// HKDF-SHA256 extract-and-expand into `out`.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .is_ok()
}

/// X25519(priv, peer_pub); None on an all-zero (low-order point) result,
/// which is a secret anyone can compute and must never key a cipher.
pub fn x25519_derive(priv_key: &[u8; 32], peer_pub: &[u8; 32]) -> Option<Key32> {
    let secret = StaticSecret::from(*priv_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_pub));
    if !shared.was_contributory() {
        return None;
    }
    Some(Zeroizing::new(*shared.as_bytes()))
}

fn x25519_public(priv_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*priv_key)).to_bytes()
}

fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Ed25519 signature over `msg` with a 32-byte seed.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// Detached Ed25519 verification (a public operation).
pub fn ed25519_verify(pub_key: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(pub_key) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
}

/// Fresh combined keypair: priv = ed_seed || x_priv, pub = ed_pub || x_pub.
pub fn generate_combined_keypair()
-> Option<(Zeroizing<[u8; HUB_KEY_RAW_LEN]>, [u8; HUB_KEY_RAW_LEN])> {
    let mut priv_key = Zeroizing::new([0u8; HUB_KEY_RAW_LEN]);
    if !random_bytes(priv_key.as_mut()) {
        return None;
    }
    let pub_key = combined_pub_from_priv(&priv_key);
    Some((priv_key, pub_key))
}

/// Split a combined private key into its halves.
pub fn split_priv(priv_key: &[u8; HUB_KEY_RAW_LEN]) -> (Key32, Key32) {
    let mut ed = Zeroizing::new([0u8; 32]);
    let mut x = Zeroizing::new([0u8; 32]);
    ed.copy_from_slice(&priv_key[..32]);
    x.copy_from_slice(&priv_key[32..]);
    (ed, x)
}

/// Combined public key (ed_pub || x_pub) from a combined private key.
pub fn combined_pub_from_priv(priv_key: &[u8; HUB_KEY_RAW_LEN]) -> [u8; HUB_KEY_RAW_LEN] {
    let (ed, x) = split_priv(priv_key);
    let mut out = [0u8; HUB_KEY_RAW_LEN];
    out[..32].copy_from_slice(&ed25519_public(&ed));
    out[32..].copy_from_slice(&x25519_public(&x));
    out
}

/// Split a 64-byte public key into its halves.
pub fn pub_halves(p: &[u8; HUB_KEY_RAW_LEN]) -> ([u8; 32], [u8; 32]) {
    let mut ed = [0u8; 32];
    let mut x = [0u8; 32];
    ed.copy_from_slice(&p[..32]);
    x.copy_from_slice(&p[32..]);
    (ed, x)
}

/// Base64 with padding and no line breaks (OpenSSL BIO_f_base64 +
/// BIO_FLAGS_BASE64_NO_NL).
pub fn b64_encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Base64 decode, tolerant of missing padding like the OpenSSL BIO it
/// replaces.  None for empty output or invalid characters.
pub fn b64_decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let v = Zeroizing::new(LENIENT.decode(s.as_bytes()).ok()?);
    if v.is_empty() {
        return None;
    }
    Some(v)
}

/// Strict decode of an Ed25519 release-signing key: only the canonical,
/// padded 44-character base64 of exactly 32 bytes, as the C updater's
/// OpenSSL decode requires.  The lenient `b64_decode` would also take the
/// unpadded 43-character spelling, so the two daemons would disagree about
/// which keys are well formed.
pub fn update_pubkey_b64_decode(b64: &str) -> Option<[u8; 32]> {
    let b = b64.as_bytes();
    if b.len() != 44 || b[43] != b'=' {
        return None;
    }
    if !b[..43]
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    {
        return None;
    }
    let v = b64_decode(b64)?;
    // A non-canonical final character (stray low bits) decodes the same 32
    // bytes; re-encoding pins the one spelling.
    if v.len() != 32 || STANDARD.encode(&v[..]) != b64 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    Some(k)
}

/// Strict decode of an 88-char combined public key: only the canonical
/// base64 of exactly 64 bytes, neither half all zero.
pub fn pubkey_b64_decode(b64: &str) -> Option<[u8; HUB_KEY_RAW_LEN]> {
    let b = b64.as_bytes();
    if b.len() != COMBINED_KEY_B64 {
        return None;
    }
    for (i, &c) in b.iter().enumerate() {
        let alpha = c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
        let ok = if i >= COMBINED_KEY_B64 - 2 {
            c == b'='
        } else {
            alpha
        };
        if !ok {
            return None;
        }
    }
    let dec = STANDARD.decode(b).ok()?;
    if dec.len() != HUB_KEY_RAW_LEN || STANDARD.encode(&dec) != b64 {
        return None;
    }
    let mut out = [0u8; HUB_KEY_RAW_LEN];
    out.copy_from_slice(&dec);
    if out[..32].iter().all(|&x| x == 0) || out[32..].iter().all(|&x| x == 0) {
        return None;
    }
    Some(out)
}

/// "ab12:cd34:ef56:7890" -- the first 8 bytes of SHA-256(pub64).
pub fn key_fingerprint(pub_key: &[u8; HUB_KEY_RAW_LEN]) -> String {
    let h = Sha256::digest(pub_key);
    format!(
        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
}

/// Lower-case hex SHA-256 of a file (the updater's archive check).
pub fn sha256_file_hex(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// key = HKDF-SHA256(ikm, salt = eph_pub, info = label || [s_x_pub] || r_x_pub)
fn seal_kdf(
    ikm: &[u8],
    eph_pub: &[u8; 32],
    label: &str,
    s_x_pub: Option<&[u8; 32]>,
    r_x_pub: &[u8; 32],
) -> Option<Key32> {
    if label.len() > 64 {
        return None;
    }
    let mut info = Vec::with_capacity(label.len() + 64);
    info.extend_from_slice(label.as_bytes());
    if let Some(s) = s_x_pub {
        info.extend_from_slice(s);
    }
    info.extend_from_slice(r_x_pub);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf_sha256(ikm, eph_pub, &info, key.as_mut()).then_some(key)
}

/// Seal `pt` to recipient X25519 key `r_x_pub`.  With a sender key
/// (s_x_priv, s_x_pub) the static term X(S, R) is mixed in: only the holder
/// of s_x_priv (or the recipient) can make a frame that opens, which is the
/// sender authentication of ~A2 and ~B2.  Without one the frame is anonymous
/// (the ~A2K lockbox).  Frame: eph_pub(32) || iv(12) || ct || tag(16).
pub fn seal(
    sender: Option<(&[u8; 32], &[u8; 32])>,
    r_x_pub: &[u8; 32],
    label: &str,
    aad: &[u8],
    pt: &[u8],
) -> Option<Vec<u8>> {
    if pt.len() > SEAL_MAX_PLAINTEXT {
        return None;
    }
    let mut eph_priv = Zeroizing::new([0u8; 32]);
    if !random_bytes(eph_priv.as_mut()) {
        return None;
    }
    let eph_pub = x25519_public(&eph_priv);
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x25519_derive(&eph_priv, r_x_pub)?.as_ref());
    let s_x_pub = match sender {
        Some((s_priv, s_pub)) => {
            ikm.extend_from_slice(x25519_derive(s_priv, r_x_pub)?.as_ref());
            Some(s_pub)
        }
        None => None,
    };
    let key = seal_kdf(&ikm, &eph_pub, label, s_x_pub, r_x_pub)?;
    let body = gcm_seal(key.as_ref(), aad, pt)?;
    let mut out = Vec::with_capacity(32 + body.len());
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&body);
    Some(out)
}

/// Inverse of [`seal`].  `s_x_pub` selects the expected sender (None for an
/// anonymous frame).  With `rk_label` the ~A2S reply key HKDF(ikm, salt =
/// eph_pub, info = rk_label || s_x_pub || r_x_pub) is derived from the same
/// exchange and returned alongside the plaintext.  None on any failure.
pub fn open_rk(
    r_x_priv: &[u8; 32],
    r_x_pub: &[u8; 32],
    s_x_pub: Option<&[u8; 32]>,
    label: &str,
    aad: &[u8],
    frame: &[u8],
    rk_label: Option<&str>,
) -> Option<(Zeroizing<Vec<u8>>, Option<Key32>)> {
    if rk_label.is_some() && s_x_pub.is_none() {
        return None;
    }
    if frame.len() < SEAL_OVERHEAD {
        return None;
    }
    let ct_len = frame.len() - SEAL_OVERHEAD;
    if ct_len > SEAL_MAX_PLAINTEXT {
        return None;
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&frame[..32]);
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x25519_derive(r_x_priv, &eph_pub)?.as_ref());
    if let Some(s) = s_x_pub {
        ikm.extend_from_slice(x25519_derive(r_x_priv, s)?.as_ref());
    }
    let key = seal_kdf(&ikm, &eph_pub, label, s_x_pub, r_x_pub)?;
    let pt = gcm_open(key.as_ref(), aad, &frame[32..])?;
    if pt.len() != ct_len {
        return None;
    }
    let rk = match rk_label {
        Some(l) => Some(seal_kdf(&ikm, &eph_pub, l, s_x_pub, r_x_pub)?),
        None => None,
    };
    Some((pt, rk))
}

/// [`open_rk`] without a reply key.
pub fn open(
    r_x_priv: &[u8; 32],
    r_x_pub: &[u8; 32],
    s_x_pub: Option<&[u8; 32]>,
    label: &str,
    aad: &[u8],
    frame: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    open_rk(r_x_priv, r_x_pub, s_x_pub, label, aad, frame, None).map(|(pt, _)| pt)
}

/// ~A2R frame under a reply key: iv(12, random) || ct || tag(16).
pub fn reply_seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Option<Vec<u8>> {
    if pt.len() > A2R_PT_MAX {
        return None;
    }
    gcm_seal(key, aad, pt)
}

/// Inverse of [`reply_seal`] (the client scripts' side; used in tests).
#[cfg(test)]
pub fn reply_open(key: &[u8; 32], aad: &[u8], frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if frame.len() < A2R_OVERHEAD || frame.len() - A2R_OVERHEAD > A2R_PT_MAX {
        return None;
    }
    gcm_open(key, aad, frame)
}

/// Wipe a byte buffer in place (OPENSSL_cleanse / secure_wipe).
pub fn wipe(buf: &mut [u8]) {
    buf.zeroize();
}

#[cfg(test)]
mod tests {

    #[test]
    fn update_key_takes_only_the_padded_spelling() {
        let k = "qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBU=";
        assert!(update_pubkey_b64_decode(k).is_some());
        // The unpadded spelling the C updater refuses...
        assert!(update_pubkey_b64_decode(k.trim_end_matches('=')).is_none());
        // ...a non-canonical last character (stray low bits)...
        assert!(update_pubkey_b64_decode("qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBV=").is_none());
        // ...and anything not 32 bytes.
        assert!(update_pubkey_b64_decode("AAAA").is_none());
    }
    use super::*;

    #[test]
    fn gcm_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let f = gcm_seal(&key, b"aad", b"hello").unwrap();
        assert_eq!(f.len(), 12 + 5 + 16);
        assert_eq!(gcm_open(&key, b"aad", &f).unwrap().as_slice(), b"hello");
        assert!(gcm_open(&key, b"aaX", &f).is_none());
        let mut bad = f.clone();
        bad[13] ^= 1;
        assert!(gcm_open(&key, b"aad", &bad).is_none());
    }

    #[test]
    fn seal_open_with_sender_and_reply_key() {
        let (spriv, spub) = generate_combined_keypair().unwrap();
        let (rpriv, rpub) = generate_combined_keypair().unwrap();
        let (_, s_x) = split_priv(&spriv);
        let (_, r_x) = split_priv(&rpriv);
        let (_, s_x_pub) = pub_halves(&spub);
        let (_, r_x_pub) = pub_halves(&rpub);
        let f = seal(
            Some((&s_x, &s_x_pub)),
            &r_x_pub,
            A2S_LABEL,
            b"ctx",
            b"1:0123456789abcdef:status",
        )
        .unwrap();
        let (pt, rk) = open_rk(
            &r_x,
            &r_x_pub,
            Some(&s_x_pub),
            A2S_LABEL,
            b"ctx",
            &f,
            Some(A2R_LABEL),
        )
        .unwrap();
        assert_eq!(pt.as_slice(), b"1:0123456789abcdef:status");
        assert!(rk.is_some());
        // Wrong sender key, wrong label, wrong AAD all fail.
        assert!(open(&r_x, &r_x_pub, Some(&r_x_pub), A2S_LABEL, b"ctx", &f).is_none());
        assert!(open(&r_x, &r_x_pub, Some(&s_x_pub), A2_LABEL, b"ctx", &f).is_none());
        assert!(open(&r_x, &r_x_pub, Some(&s_x_pub), A2S_LABEL, b"ctX", &f).is_none());
        let rk = rk.unwrap();
        let rf = reply_seal(&rk, b"r", b"0:0:hi").unwrap();
        assert_eq!(reply_open(&rk, b"r", &rf).unwrap().as_slice(), b"0:0:hi");
    }

    #[test]
    fn pubkey_decode_is_strict() {
        let (_, p) = generate_combined_keypair().unwrap();
        let b = b64_encode(&p);
        assert_eq!(pubkey_b64_decode(&b), Some(p));
        assert!(pubkey_b64_decode(&b[..87]).is_none());
        assert!(pubkey_b64_decode(&b64_encode(&[0u8; 64])).is_none());
        assert_eq!(key_fingerprint(&p).len(), 19);
    }

    #[test]
    fn x25519_rejects_low_order() {
        assert!(x25519_derive(&[1u8; 32], &[0u8; 32]).is_none());
    }

    #[test]
    fn uuid_shape() {
        let u = gen_uuid_v4().unwrap();
        assert!(crate::cstr::is_uuid(&u));
        assert_eq!(&u[14..15], "4");
    }

    #[test]
    fn ed25519_rfc8032_vector1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let seed: [u8; 32] =
            hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(ed25519_public(&seed), pk);
        let sig = ed25519_sign(&seed, b"");
        assert!(ed25519_verify(&pk, b"", &sig));
        assert_eq!(sig[..8], [0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72]);
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        o
    }
}
