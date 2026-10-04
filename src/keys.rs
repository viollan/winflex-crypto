//! Ключевой набор участника: пара Ed25519 (подпись) + пара X25519 (шифрование).

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::{random_bytes, Error, Result, KEY_LEN};

/// Ключевой набор. Все поля — base64 (стандартный алфавит, с выравниванием).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeySet {
    /// Зерно Ed25519 (32 байта) — секретная часть ключа подписи.
    pub sign_secret: String,
    pub sign_public: String,
    /// Секретный скаляр X25519 (32 байта).
    pub box_secret: String,
    pub box_public: String,
}

impl KeySet {
    /// Создать новый набор из случайных байт ОС.
    pub fn generate() -> Result<KeySet> {
        let seed: [u8; KEY_LEN] = random_bytes(KEY_LEN)?.try_into().unwrap();
        let box_sk: [u8; KEY_LEN] = random_bytes(KEY_LEN)?.try_into().unwrap();
        Ok(Self::from_secrets(&seed, &box_sk))
    }

    /// Восстановить набор из секретных частей (открытые вычисляются).
    pub fn from_secrets(sign_seed: &[u8; KEY_LEN], box_secret: &[u8; KEY_LEN]) -> KeySet {
        let signing = ed25519_dalek::SigningKey::from_bytes(sign_seed);
        let box_sk = crypto_box::SecretKey::from(*box_secret);
        KeySet {
            sign_secret: STANDARD.encode(sign_seed),
            sign_public: STANDARD.encode(signing.verifying_key().to_bytes()),
            // to_bytes() возвращает скаляр в виде, как он был задан (без «зажима»), — как в libsodium.
            box_secret: STANDARD.encode(box_sk.to_bytes()),
            box_public: STANDARD.encode(box_sk.public_key().as_bytes()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("KeySet сериализуется всегда")
    }

    pub fn from_json(json: &str) -> Result<KeySet> {
        let k: KeySet = serde_json::from_str(json).map_err(|e| Error::new(format!("ключевой набор: {e}")))?;
        // Проверяем согласованность: открытые части должны вычисляться из секретных.
        let seed = decode32(&k.sign_secret, "sign_secret")?;
        let box_sk = decode32(&k.box_secret, "box_secret")?;
        if Self::from_secrets(&seed, &box_sk) != k {
            return Err(Error::new("ключевой набор: открытые ключи не соответствуют секретным"));
        }
        Ok(k)
    }
}

/// Декодировать base64 в 32 байта.
pub fn decode32(b64: &str, what: &str) -> Result<[u8; KEY_LEN]> {
    let v = STANDARD
        .decode(b64.trim())
        .map_err(|_| Error::new(format!("{what}: неверный base64")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| Error::new(format!("{what}: ожидается {KEY_LEN} байт, получено {}", v.len())))
}
