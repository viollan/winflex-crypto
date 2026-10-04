//! winFlexCrypto — криптография для 1С:Предприятие 8.3 во внешней компоненте Native API.
//!
//! Подключение в 1С:
//! ```bsl
//! ПодключитьВнешнююКомпоненту("ОбщийМакет.winFlexCrypto", "winFlex", ТипВнешнейКомпоненты.Native);
//! Крипто = Новый("AddIn.winFlex.Crypto");
//! ```
//!
//! Примитивы (совместимы с libsodium / PyNaCl байт в байт — см. `testdata/vectors.json`):
//! - подпись — Ed25519 (секретный ключ хранится как 32-байтовое зерно);
//! - шифрование на открытый ключ — запечатанный конверт libsodium
//!   (`crypto_box_seal`: X25519 + XSalsa20-Poly1305), как `nacl.public.SealedBox`;
//! - шифрование паролем — Argon2id + XChaCha20-Poly1305 (формат `WFC1`, `password.rs`);
//! - SHA-256, случайные байты ОС, отпечаток открытых ключей.
//!
//! Методы компоненты — в `component.rs` (имена русские и английские, регистр не важен).

mod component;
mod error;
pub mod keys;
pub mod password;

pub use error::{Error, Result};

use std::ffi::{c_int, c_long, c_void};

use addin1c::{create_component, destroy_component, name, AttachType};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Длина ключей и зерна Ed25519/X25519.
pub const KEY_LEN: usize = 32;
/// Длина подписи Ed25519.
pub const SIGNATURE_LEN: usize = 64;

fn key32(bytes: &[u8], what: &str) -> Result<[u8; KEY_LEN]> {
    bytes
        .try_into()
        .map_err(|_| Error::new(format!("{what}: ожидается {KEY_LEN} байт, получено {}", bytes.len())))
}

/// Подписать данные секретным ключом (зерном) Ed25519.
pub fn sign(data: &[u8], sign_secret: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
    let key = SigningKey::from_bytes(&key32(sign_secret, "секретный ключ подписи")?);
    Ok(key.sign(data).to_bytes())
}

/// Проверить подпись Ed25519. `Ok(false)` — подпись неверна; `Err` — неверный формат ключа или подписи.
pub fn verify(data: &[u8], signature: &[u8], sign_public: &[u8]) -> Result<bool> {
    let key = VerifyingKey::from_bytes(&key32(sign_public, "открытый ключ подписи")?)
        .map_err(|_| Error::new("открытый ключ подписи: не точка кривой"))?;
    let sig: [u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| Error::new(format!("подпись: ожидается {SIGNATURE_LEN} байт, получено {}", signature.len())))?;
    // verify_strict отвергает слабые ключи и неканонические подписи.
    Ok(key.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&sig)).is_ok())
}

/// Зашифровать данные на открытый ключ X25519 (запечатанный конверт libsodium).
pub fn seal(data: &[u8], box_public: &[u8]) -> Result<Vec<u8>> {
    let pk = crypto_box::PublicKey::from(key32(box_public, "открытый ключ шифрования")?);
    pk.seal(&mut crypto_box::aead::OsRng, data)
        .map_err(|_| Error::new("ошибка шифрования"))
}

/// Расшифровать запечатанный конверт секретным ключом X25519.
pub fn unseal(data: &[u8], box_secret: &[u8]) -> Result<Vec<u8>> {
    let sk = crypto_box::SecretKey::from(key32(box_secret, "секретный ключ шифрования")?);
    sk.unseal(data)
        .map_err(|_| Error::new("не удалось расшифровать: неверный ключ или данные повреждены"))
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Криптостойкие случайные байты из ОС.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    if len > 1024 * 1024 {
        return Err(Error::new("слишком много случайных байт за один вызов (максимум 1 МБ)"));
    }
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|e| Error::new(format!("генератор случайных чисел ОС: {e}")))?;
    Ok(buf)
}

/// Короткий отпечаток открытых ключей для сверки человеком: 5 групп по 4 hex-символа
/// (первые 10 байт SHA-256 от открытого ключа подписи и открытого ключа шифрования).
pub fn fingerprint(sign_public: &[u8], box_public: &[u8]) -> Result<String> {
    let mut h = Sha256::new();
    h.update(key32(sign_public, "открытый ключ подписи")?);
    h.update(key32(box_public, "открытый ключ шифрования")?);
    let d = h.finalize();
    let hex: String = d[..10].iter().map(|b| format!("{b:02X}")).collect();
    Ok(hex
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-"))
}

// ---------- точки входа Native API ----------

/// # Safety
///
/// `component` — указатель от платформы, не null.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn GetClassObject(_name: *const u16, component: *mut *mut c_void) -> c_long {
    // Класс один — имя не проверяем.
    create_component(component, component::Crypto::new())
}

/// # Safety
///
/// `component` получен из `GetClassObject`, вызывается один раз.
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn DestroyObject(component: *mut *mut c_void) -> c_long {
    destroy_component(component)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn GetClassNames() -> *const u16 {
    name!("Crypto").as_ptr()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn SetPlatformCapabilities(_capabilities: c_int) -> c_int {
    3
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn GetAttachType() -> AttachType {
    AttachType::Any
}

#[cfg(test)]
mod tests;
