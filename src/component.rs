//! Объект компоненты `Crypto`: таблица методов, разбор параметров, перехват ошибок и паник.
//!
//! Ошибка метода: метод возвращает «ложь» платформе — в 1С возникает исключение, а текст
//! причины доступен в свойстве `ОписаниеОшибки` (`LastError`).
//!
//! Двоичные параметры (данные, ключи, подписи) принимаются как `ДвоичныеДанные`;
//! ключи и подписи — также строкой base64 (так их удобно хранить в константах);
//! данные — также строкой (кодируется в UTF-8).

use std::panic::{catch_unwind, AssertUnwindSafe};

use addin1c::{name, CStr1C, ParamValue, RawAddin, Variant};
use base64::{engine::general_purpose::STANDARD, Engine};

use crate::{keys::KeySet, password, Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Crypto {
    last_error: String,
}

impl Crypto {
    pub fn new() -> Self {
        Crypto { last_error: String::new() }
    }
}

type MethodFn = fn(&mut [Variant], &mut Variant) -> Result<()>;

struct MethodDef {
    en: &'static CStr1C,
    ru: &'static CStr1C,
    params: usize,
    func: MethodFn,
}

const METHODS: &[MethodDef] = &[
    MethodDef { en: name!("GenerateKeys"), ru: name!("СоздатьКлючи"), params: 0, func: generate_keys },
    MethodDef { en: name!("PublicKeys"), ru: name!("ОткрытыеКлючи"), params: 1, func: public_keys },
    MethodDef { en: name!("Sign"), ru: name!("Подписать"), params: 2, func: sign },
    MethodDef { en: name!("Verify"), ru: name!("ПроверитьПодпись"), params: 3, func: verify },
    MethodDef { en: name!("Seal"), ru: name!("ЗашифроватьДля"), params: 2, func: seal },
    MethodDef { en: name!("Unseal"), ru: name!("Расшифровать"), params: 2, func: unseal },
    MethodDef { en: name!("EncryptWithPassword"), ru: name!("ЗашифроватьПаролем"), params: 2, func: encrypt_password },
    MethodDef { en: name!("DecryptWithPassword"), ru: name!("РасшифроватьПаролем"), params: 2, func: decrypt_password },
    MethodDef { en: name!("SHA256"), ru: name!("SHA256"), params: 1, func: sha256 },
    MethodDef { en: name!("RandomBytes"), ru: name!("СлучайныеБайты"), params: 1, func: random_bytes },
    MethodDef { en: name!("Fingerprint"), ru: name!("Отпечаток"), params: 2, func: fingerprint },
    MethodDef { en: name!("Version"), ru: name!("Версия"), params: 0, func: version },
];

const PROP_LAST_ERROR: usize = 0;
const PROPS: &[(&CStr1C, &CStr1C)] = &[(name!("LastError"), name!("ОписаниеОшибки"))];

/// Сравнение имён без учёта регистра (платформа передаёт имя так, как оно написано в коде).
fn find(name: &CStr1C, candidates: impl Iterator<Item = (usize, &'static CStr1C)>) -> Option<usize> {
    let wanted = lower(name);
    candidates.into_iter().find(|(_, c)| lower(c) == wanted).map(|(i, _)| i)
}

fn lower(s: &CStr1C) -> String {
    let units: Vec<u16> = s.iter().copied().take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&units).to_lowercase()
}

impl RawAddin for Crypto {
    fn register_extension_as(&mut self) -> &CStr1C {
        // Имя класса в Новый("AddIn.<Имя>.Crypto") платформа берёт отсюда.
        name!("Crypto")
    }

    fn get_n_props(&mut self) -> usize {
        PROPS.len()
    }

    fn find_prop(&mut self, name: &CStr1C) -> Option<usize> {
        find(name, PROPS.iter().enumerate().flat_map(|(i, (en, ru))| [(i, *en), (i, *ru)]))
    }

    fn get_prop_name(&mut self, num: usize, alias: usize) -> Option<&'static CStr1C> {
        PROPS.get(num).map(|(en, ru)| if alias == 0 { *en } else { *ru })
    }

    fn get_prop_val(&mut self, num: usize, val: &mut Variant) -> bool {
        match num {
            PROP_LAST_ERROR => val.set_str1c(self.last_error.as_str()).is_ok(),
            _ => false,
        }
    }

    fn is_prop_readable(&mut self, num: usize) -> bool {
        num < PROPS.len()
    }

    fn get_n_methods(&mut self) -> usize {
        METHODS.len()
    }

    fn find_method(&mut self, name: &CStr1C) -> Option<usize> {
        find(name, METHODS.iter().enumerate().flat_map(|(i, m)| [(i, m.en), (i, m.ru)]))
    }

    fn get_method_name(&mut self, num: usize, alias: usize) -> Option<&'static CStr1C> {
        METHODS.get(num).map(|m| if alias == 0 { m.en } else { m.ru })
    }

    fn get_n_params(&mut self, num: usize) -> usize {
        METHODS.get(num).map_or(0, |m| m.params)
    }

    fn has_ret_val(&mut self, num: usize) -> bool {
        num < METHODS.len()
    }

    fn call_as_func(&mut self, num: usize, params: &mut [Variant], val: &mut Variant) -> bool {
        self.last_error.clear();
        let Some(m) = METHODS.get(num) else {
            return false;
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            if params.len() < m.params {
                return Err(Error::new(format!("ожидается параметров: {}", m.params)));
            }
            (m.func)(params, val)
        }));
        match result {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                self.last_error = e.to_string();
                false
            }
            Err(panic) => {
                let text = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "неизвестная причина".into());
                self.last_error = format!("внутренняя ошибка компоненты: {text}");
                false
            }
        }
    }

    fn call_as_proc(&mut self, _num: usize, _params: &mut [Variant]) -> bool {
        // Все методы — функции; вызов процедурой не поддерживается.
        self.last_error = "метод компоненты нужно вызывать как функцию".into();
        false
    }
}

// ---------- разбор параметров ----------

fn bytes(v: &Variant, what: &str) -> Result<Vec<u8>> {
    match v.get() {
        ParamValue::Blob(b) => Ok(b.to_vec()),
        ParamValue::Str(s) => Ok(String::from_utf16(s)
            .map_err(|_| Error::new(format!("{what}: строка не в UTF-16")))?
            .into_bytes()),
        _ => Err(Error::new(format!("{what}: ожидаются ДвоичныеДанные или Строка"))),
    }
}

fn key_bytes(v: &Variant, what: &str) -> Result<Vec<u8>> {
    match v.get() {
        ParamValue::Blob(b) => Ok(b.to_vec()),
        ParamValue::Str(s) => {
            let text = String::from_utf16(s).map_err(|_| Error::new(format!("{what}: строка не в UTF-16")))?;
            // 1С вставляет переносы строк в длинный base64 — убираем любые пробельные символы.
            let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
            STANDARD.decode(clean).map_err(|_| Error::new(format!("{what}: неверный base64")))
        }
        _ => Err(Error::new(format!("{what}: ожидаются ДвоичныеДанные или строка base64"))),
    }
}

fn string(v: &Variant, what: &str) -> Result<String> {
    match v.get() {
        ParamValue::Str(s) => String::from_utf16(s).map_err(|_| Error::new(format!("{what}: строка не в UTF-16"))),
        _ => Err(Error::new(format!("{what}: ожидается Строка"))),
    }
}

fn number(v: &Variant, what: &str) -> Result<i64> {
    match v.get() {
        ParamValue::I32(n) => Ok(n as i64),
        ParamValue::F64(f) if f.fract() == 0.0 && f.abs() < 1e15 => Ok(f as i64),
        _ => Err(Error::new(format!("{what}: ожидается целое Число"))),
    }
}

fn ret_blob(val: &mut Variant, data: &[u8]) -> Result<()> {
    val.set_blob(data).map_err(|_| Error::new("не удалось выделить память под результат"))
}

fn ret_str(val: &mut Variant, s: &str) -> Result<()> {
    val.set_str1c(s).map_err(|_| Error::new("не удалось выделить память под результат"))
}

// ---------- методы ----------

fn generate_keys(_: &mut [Variant], val: &mut Variant) -> Result<()> {
    ret_str(val, &KeySet::generate()?.to_json())
}

/// Открытая часть набора ключей (JSON без секретов) — её можно передавать другой стороне.
fn public_keys(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let k = KeySet::from_json(&string(&p[0], "КлючиJSON")?)?;
    ret_str(val, &serde_json::json!({ "sign_public": k.sign_public, "box_public": k.box_public }).to_string())
}

fn sign(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = bytes(&p[0], "Данные")?;
    let sig = crate::sign(&data, &key_bytes(&p[1], "СекретныйКлючПодписи")?)?;
    ret_blob(val, &sig)
}

fn verify(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = bytes(&p[0], "Данные")?;
    let ok = crate::verify(&data, &key_bytes(&p[1], "Подпись")?, &key_bytes(&p[2], "ОткрытыйКлючПодписи")?)?;
    val.set_bool(ok);
    Ok(())
}

fn seal(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = bytes(&p[0], "Данные")?;
    ret_blob(val, &crate::seal(&data, &key_bytes(&p[1], "ОткрытыйКлючШифрования")?)?)
}

fn unseal(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = key_bytes(&p[0], "Данные")?;
    ret_blob(val, &crate::unseal(&data, &key_bytes(&p[1], "СекретныйКлючШифрования")?)?)
}

fn encrypt_password(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = bytes(&p[0], "Данные")?;
    ret_blob(val, &password::encrypt(&data, &string(&p[1], "Пароль")?)?)
}

fn decrypt_password(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let data = key_bytes(&p[0], "Данные")?;
    ret_blob(val, &password::decrypt(&data, &string(&p[1], "Пароль")?)?)
}

fn sha256(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    ret_blob(val, &crate::sha256(&bytes(&p[0], "Данные")?))
}

fn random_bytes(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let n = number(&p[0], "Количество")?;
    if n < 0 {
        return Err(Error::new("Количество: должно быть неотрицательным"));
    }
    ret_blob(val, &crate::random_bytes(n as usize)?)
}

fn fingerprint(p: &mut [Variant], val: &mut Variant) -> Result<()> {
    let fp = crate::fingerprint(&key_bytes(&p[0], "ОткрытыйКлючПодписи")?, &key_bytes(&p[1], "ОткрытыйКлючШифрования")?)?;
    ret_str(val, &fp)
}

fn version(_: &mut [Variant], val: &mut Variant) -> Result<()> {
    ret_str(val, VERSION)
}
