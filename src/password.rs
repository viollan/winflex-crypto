//! Шифрование паролем: ключ из пароля — Argon2id, шифр — XChaCha20-Poly1305.
//!
//! Формат: `WFC1 | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt[16] | nonce[24] | шифротекст+тег`.
//! Заголовок до шифротекста — связанные данные AEAD, подмена параметров ломает расшифровку.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::{random_bytes, Error, Result};

const MAGIC: &[u8; 4] = b"WFC1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 12 + SALT_LEN + NONCE_LEN;

/// Параметры Argon2id по умолчанию: 64 МиБ, 3 прохода, 1 поток (рекомендация OWASP).
pub const DEFAULT_M_COST: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

// Верхние границы при расшифровке — чтобы испорченный заголовок не заставил выделить гигабайты.
const MAX_M_COST: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 20;
const MAX_P_COST: u32 = 8;

fn derive(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32]> {
    if password.is_empty() {
        return Err(Error::new("пароль не задан"));
    }
    let params = Params::new(m, t, p, Some(32)).map_err(|e| Error::new(format!("параметры Argon2: {e}")))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::new(format!("Argon2: {e}")))?;
    Ok(key)
}

pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    encrypt_with(data, password, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST)
}

pub fn encrypt_with(data: &[u8], password: &str, m: u32, t: u32, p: u32) -> Result<Vec<u8>> {
    let salt = random_bytes(SALT_LEN)?;
    let nonce = random_bytes(NONCE_LEN)?;
    let key = derive(password, &salt, m, t, p)?;

    let mut out = Vec::with_capacity(HEADER_LEN + data.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&m.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&p.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);

    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: data, aad: &out })
        .map_err(|_| Error::new("ошибка шифрования"))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + 16 || &data[..4] != MAGIC {
        return Err(Error::new("данные не зашифрованы паролем (нет заголовка WFC1)"));
    }
    let u32_at = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    let (m, t, p) = (u32_at(4), u32_at(8), u32_at(12));
    if m > MAX_M_COST || t > MAX_T_COST || p > MAX_P_COST {
        return Err(Error::new("недопустимые параметры Argon2 в заголовке"));
    }
    let salt = &data[16..16 + SALT_LEN];
    let nonce = &data[16 + SALT_LEN..HEADER_LEN];
    let key = derive(password, salt, m, t, p)?;
    XChaCha20Poly1305::new((&key).into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: &data[HEADER_LEN..], aad: &data[..HEADER_LEN] },
        )
        .map_err(|_| Error::new("неверный пароль или данные повреждены"))
}
