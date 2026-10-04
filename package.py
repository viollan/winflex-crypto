"""Собрать компоненту под 4 цели и упаковать в ZIP для макета 1С.

Запуск: python package.py [--no-build]
Результат: dist/winFlexCrypto.zip (MANIFEST.XML + DLL/SO для Windows и Linux, x86 и x64).
Сборка — build.cmd zigbuild (Rust + cargo-zigbuild + zig): одна машина Windows собирает все 4 цели.
"""

import pathlib
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
TARGET = ROOT / "target"
DIST = ROOT / "dist"

# (цель cargo, путь к результату, имя в архиве, ОС, архитектура в MANIFEST.XML)
BUILDS = [
    ("x86_64-pc-windows-gnu", "x86_64-pc-windows-gnu/release/winflex_crypto.dll", "winFlexCrypto_win64.dll", "Windows", "x86_64"),
    ("i686-pc-windows-gnu", "i686-pc-windows-gnu/release/winflex_crypto.dll", "winFlexCrypto_win32.dll", "Windows", "i386"),
    ("x86_64-unknown-linux-gnu.2.17", "x86_64-unknown-linux-gnu/release/libwinflex_crypto.so", "libwinFlexCrypto_lin64.so", "Linux", "x86_64"),
    ("i686-unknown-linux-gnu.2.17", "i686-unknown-linux-gnu/release/libwinflex_crypto.so", "libwinFlexCrypto_lin32.so", "Linux", "i386"),
]


def main() -> None:
    if "--no-build" not in sys.argv:
        for target, *_ in BUILDS:
            subprocess.run(["cmd", "/c", str(ROOT / "build.cmd"), "zigbuild", "--release", "--target", target], check=True)

    manifest = ['<?xml version="1.0" encoding="UTF-8"?>',
                '<bundle xmlns="http://v8.1c.ru/8.2/addin/bundle" name="winFlexCrypto">']
    for _, _, name, os_, arch in BUILDS:
        manifest.append(f'\t<component os="{os_}" path="{name}" type="native" arch="{arch}"/>')
    manifest.append("</bundle>")

    DIST.mkdir(exist_ok=True)
    out = DIST / "winFlexCrypto.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("MANIFEST.XML", "\r\n".join(manifest) + "\r\n")
        for _, rel, name, *_ in BUILDS:
            z.write(TARGET / rel, name)
    print(out, out.stat().st_size, "байт")


if __name__ == "__main__":
    main()
