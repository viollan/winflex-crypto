//! На Windows (GNU-компоновщик и lld из zig) без .def экспортируются все символы Rust —
//! оставляем только точки входа Native API (exports.def).
fn main() {
    println!("cargo:rerun-if-changed=exports.def");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let def = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("exports.def");
        println!("cargo:rustc-cdylib-link-arg={}", def.display());
    }
}
