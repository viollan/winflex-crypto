"""XML-исходники тестовой обработки WFCТестыКомпоненты (для vrunner compile / конфигуратора).

Запуск после package.py: python test\\1c\\make_src.py <каталог-образец>
  <каталог-образец> — XML-выгрузка любой внешней обработки с формой «Форма» и двумя макетами «Двоичные данные»
  с именами «Компонента» и «Векторы» (структура файлов как у выгрузки конфигуратора 8.3.27, формат 2.17).
Результат: build/test1c/src/WFCТестыКомпоненты(.xml) — модуль формы из test/1c/Module.bsl,
макет «Компонента» = dist/winFlexCrypto.zip, «Векторы» = testdata/vectors.json, свои постоянные UUID.
Файлы BSL и XML — UTF-8 с BOM, CRLF.
"""
import re
import shutil
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NAME = "WFCТестыКомпоненты"
OUT = HERE / "src"
# Идентификаторы объекта: uuid="…", ObjectId, TypeId, ValueId. ClassId — постоянный идентификатор класса платформы.
UUID_RE = re.compile(r'(uuid="|<xr:(?:ObjectId|TypeId|ValueId)>)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')


def bom_crlf(text: str) -> bytes:
    return b"\xef\xbb\xbf" + text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def skeleton(sample: Path) -> None:
    xml = next(sample.glob("*.xml"))
    old = xml.stem
    if OUT.exists():
        shutil.rmtree(OUT)
    shutil.copytree(sample / old, OUT / NAME)
    shutil.copy(xml, OUT / f"{NAME}.xml")

    # Постоянные UUID от имени обработки и старого UUID: пересборка не меняет объект.
    def new_uuid(m):
        return m.group(1) + str(uuid.uuid5(uuid.NAMESPACE_URL, f"winflex_crypto/{NAME}/{m.group(2)}"))

    for p in [OUT / f"{NAME}.xml", *(OUT / NAME).rglob("*.xml")]:
        t = p.read_bytes().decode("utf-8-sig")
        t = UUID_RE.sub(new_uuid, t.replace(old, NAME))
        if p.name == f"{NAME}.xml":
            # Синоним обработки (первый ru-синоним в файле).
            t = re.sub(r"(<Synonym>\s*<v8:item>\s*<v8:lang>ru</v8:lang>\s*<v8:content>)[^<]*(</v8:content>)",
                       r"\1Тесты компоненты winFlexCrypto\2", t, count=1)
        p.write_bytes(bom_crlf(t))


def main() -> None:
    if len(sys.argv) > 2 and sys.argv[1] == "--skeleton":
        skeleton(Path(sys.argv[2]))
    (OUT / NAME / "Forms/Форма/Ext/Form/Module.bsl").write_bytes(
        bom_crlf((HERE / "Module.bsl").read_text(encoding="utf-8")))
    (OUT / NAME / "Templates/Компонента/Ext/Template.bin").write_bytes((ROOT / "dist/winFlexCrypto.zip").read_bytes())
    (OUT / NAME / "Templates/Векторы/Ext/Template.bin").write_bytes((ROOT / "testdata/vectors.json").read_bytes())
    print(OUT)


if __name__ == "__main__":
    main()
