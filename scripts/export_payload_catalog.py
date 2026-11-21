"""Read the human-managed workbook into a versioned payload catalog; never write XLSX."""
import argparse
import hashlib
import io
import json
from pathlib import Path

import openpyxl

TIERS = ("light", "medium", "hard")
MODES = ("append", "replace", "array")
CONTEXTS = {"query", "form", "json-string", "json-value", "raw"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rows(sheet, required):
    headers = [cell.value for cell in sheet[5]]
    require(len(headers) == len(set(headers)), f"{sheet.title}: duplicate column")
    require(set(required) <= set(headers), f"{sheet.title}: missing required column")
    for row in sheet.iter_rows(min_row=6):
        if all(cell.value is None for cell in row):
            continue
        require(all(cell.data_type not in ("f", "e") for cell in row),
                f"{sheet.title} row {row[0].row}: formula/error is not a literal definition")
        yield dict(zip(headers, (cell.value for cell in row)))


def text(value, label):
    require(isinstance(value, str), f"{label}: expected text")
    return value


def compile_bytes(workbook_bytes):
    # Parsing and hashing the same snapshot prevents a mid-read workbook edit mismatch.
    workbook = openpyxl.load_workbook(io.BytesIO(workbook_bytes), read_only=True, data_only=False)
    try:
        payloads = []
        ids = set()
        for row in rows(workbook["Payloads"], ["Payload ID", "挿入位置", "最小tier", "Payload原文（JSON文字列表記）", "適用文脈", "分類", "観測・追加確認", "適用注意"]):
            ident = text(row["Payload ID"], "Payload ID")
            require(ident.strip() and ident not in ids, "Blank/duplicate payload ID")
            ids.add(ident)
            mode, tier = row["挿入位置"], row["最小tier"]
            require(mode in MODES and tier in TIERS, f"{ident}: unknown mode/tier")
            raw = json.loads(text(row["Payload原文（JSON文字列表記）"], ident))
            require(isinstance(raw, str), f"{ident}: JSON payload must encode a string")
            contexts = [s.strip() for s in text(row["適用文脈"], ident).split(",")]
            require(contexts and len(contexts) == len(set(contexts)) and set(contexts) <= CONTEXTS,
                    f"{ident}: invalid contexts")
            payloads.append(dict(id=ident, mode=mode, minimumTier=tier, raw=raw, contexts=contexts,
                                category=text(row["分類"], ident), guidance=text(row["観測・追加確認"], ident),
                                caution=text(row["適用注意"], ident)))
        require(payloads, "Empty payload catalog")
        grep = []
        grep_ids = set()
        for row in rows(workbook["Grep match"], ["モード", "識別名", "Grep match文字列（正規表現）"]):
            mode = row["モード"]
            name = text(row["識別名"], "Grep name")
            expression = text(row["Grep match文字列（正規表現）"], name)
            require(mode in MODES and name.strip() and expression, "Invalid grep definition")
            require((mode, name) not in grep_ids, "Duplicate grep identity")
            grep_ids.add((mode, name))
            grep.append(dict(mode=mode, name=name, regex=expression))
        return dict(workbookSha256=hashlib.sha256(workbook_bytes).hexdigest(), payloads=payloads, grep=grep)
    finally:
        workbook.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workbook", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    require(args.workbook.resolve() != args.output.resolve(), "Never overwrite the workbook")
    catalog = compile_bytes(args.workbook.read_bytes())
    # Exclusive create protects earlier run snapshots.
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(catalog, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"payloadCount": len(catalog["payloads"]), "grepCount": len(catalog["grep"]),
                      "workbookSha256": catalog["workbookSha256"]}))


if __name__ == "__main__":
    main()
