@echo off
rem cargo with the Rust toolchain from C:\rust (RUSTUP_HOME/CARGO_HOME without Cyrillic in path) and zig for cross builds.
rem Usage: build.cmd <cargo args>, e.g. build.cmd test; build.cmd zigbuild --release --target x86_64-pc-windows-gnu
rem Paths can be overridden by environment variables before the call.
if not defined RUSTUP_HOME set RUSTUP_HOME=C:\rust\rustup
if not defined CARGO_HOME set CARGO_HOME=C:\rust\cargo
if not defined CARGO_ZIGBUILD_ZIG_PATH set CARGO_ZIGBUILD_ZIG_PATH=C:\Python314\Lib\site-packages\ziglang\zig.exe
set PATH=%CARGO_HOME%\bin;C:\Python314\Scripts;%PATH%
cd /d "%~dp0"
cargo %*
