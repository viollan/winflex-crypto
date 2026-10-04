//! Совместимость с эталоном PyNaCl (testdata/vectors.json) и самопроверки.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::{keys::KeySet, password, *};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap()
}

fn b(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn keyset_matches_pynacl() {
    let v = vectors();
    let k = &v["keys"];
    let rust = KeySet::from_secrets(
        &b(&k["sign_secret"]).try_into().unwrap(),
        &b(&k["box_secret"]).try_into().unwrap(),
    );
    assert_eq!(rust.sign_public, k["sign_public"].as_str().unwrap());
    assert_eq!(rust.box_public, k["box_public"].as_str().unwrap());
    assert_eq!(KeySet::from_json(&rust.to_json()).unwrap(), rust);
}

#[test]
fn fingerprint_matches_pynacl() {
    let v = vectors();
    let fp = fingerprint(&b(&v["keys"]["sign_public"]), &b(&v["keys"]["box_public"])).unwrap();
    assert_eq!(fp, v["fingerprint"].as_str().unwrap());
}

#[test]
fn sha256_matches() {
    let v = vectors();
    assert_eq!(sha256(&b(&v["data_b64"])).to_vec(), b(&v["sha256_b64"]));
}

#[test]
fn signature_matches_pynacl() {
    let v = vectors();
    let data = b(&v["data_b64"]);
    let sig = sign(&data, &b(&v["keys"]["sign_secret"])).unwrap();
    // Ed25519 детерминирована — подпись обязана совпасть байт в байт.
    assert_eq!(sig.to_vec(), b(&v["signature_b64"]));
    let pk = b(&v["keys"]["sign_public"]);
    assert!(verify(&data, &sig, &pk).unwrap());
    let mut bad = data.clone();
    bad[0] ^= 1;
    assert!(!verify(&bad, &sig, &pk).unwrap());
    assert!(verify(&data, &sig[..63], &pk).is_err());
}

#[test]
fn unseal_pynacl_sealed_box() {
    let v = vectors();
    let plain = unseal(&b(&v["sealed_b64"]), &b(&v["keys"]["box_secret"])).unwrap();
    assert_eq!(plain, b(&v["data_b64"]));
}

#[test]
fn seal_roundtrip_and_wrong_key() {
    let k = KeySet::generate().unwrap();
    let other = KeySet::generate().unwrap();
    let ct = seal(b"secret", &STANDARD.decode(&k.box_public).unwrap()).unwrap();
    assert_eq!(unseal(&ct, &STANDARD.decode(&k.box_secret).unwrap()).unwrap(), b"secret");
    assert!(unseal(&ct, &STANDARD.decode(&other.box_secret).unwrap()).is_err());
}

#[test]
fn password_roundtrip() {
    // Облегчённые параметры, чтобы тест шёл быстро; формат тот же.
    let ct = password::encrypt_with(b"root key", "пароль", 256, 1, 1).unwrap();
    assert_eq!(password::decrypt(&ct, "пароль").unwrap(), b"root key");
    assert!(password::decrypt(&ct, "Пароль").is_err());
    let mut bad = ct.clone();
    bad[5] ^= 1; // параметры Argon2 — связанные данные
    assert!(password::decrypt(&bad, "пароль").is_err());
    assert!(password::decrypt(b"junk", "пароль").is_err());
    assert!(password::encrypt(b"x", "").is_err());
}

#[test]
fn password_default_params() {
    let ct = password::encrypt(b"k", "p").unwrap();
    assert_eq!(password::decrypt(&ct, "p").unwrap(), b"k");
}

#[test]
fn keyset_json_rejects_mismatch() {
    let mut k = KeySet::generate().unwrap();
    k.box_public = KeySet::generate().unwrap().box_public;
    assert!(KeySet::from_json(&serde_json::to_string(&k).unwrap()).is_err());
}

#[test]
fn random_bytes_len() {
    assert_eq!(random_bytes(0).unwrap().len(), 0);
    assert_eq!(random_bytes(48).unwrap().len(), 48);
    assert_ne!(random_bytes(32).unwrap(), random_bytes(32).unwrap());
    assert!(random_bytes(2 * 1024 * 1024).is_err());
}
