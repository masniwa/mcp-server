package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class PayloadWorkbookTest {
    @org.junit.jupiter.api.io.TempDir lateinit var root: java.nio.file.Path

    @Test fun `workbook alone needs no catalog and still refuses invalid source`() {
        val source = root.resolve("source.xlsx")
        val bytes = fixture()
        java.nio.file.Files.write(source, bytes)
        assertEquals(readPayloadWorkbook(bytes), loadPayloadProfile(null, source))
        java.nio.file.Files.list(root).use { assertEquals(1L, it.count()) }
        java.nio.file.Files.write(source, fixture(formula = true))
        assertThrows(IllegalArgumentException::class.java) { loadPayloadProfile(null, source) }
    }
    private fun fixture(formula: Boolean = false, external: Boolean = false, dtd: Boolean = false): ByteArray {
        fun cell(column: Char, row: Int, value: String) = "<c r=\"$column$row\" t=\"inlineStr\"><is><t>${value.replace("&", "&amp;").replace("<", "&lt;")}</t></is></c>"
        fun sheet(headers: List<String>, values: List<String>): String = "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row r=\"5\">" +
            headers.mapIndexed { i, v -> cell('A' + i, 5, v) }.joinToString("") + "</row><row r=\"6\">" +
            values.mapIndexed { i, v -> if (i == 0 && v == "P1") "<c r=\"A6\" t=\"s\"><v>0</v>${if (formula) "<f>1+1</f>" else ""}</c>" else cell('A' + i, 6, v) }.joinToString("") + "</row></sheetData></worksheet>"
        val data = linkedMapOf(
            "xl/workbook.xml" to (if (dtd) "<!DOCTYPE workbook [<!ENTITY bad SYSTEM 'file:///forbidden'>]>" else "") + "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Payloads\" r:id=\"a\"/><sheet name=\"Grep match\" r:id=\"b\"/></sheets></workbook>",
            "xl/_rels/workbook.xml.rels" to "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"a\" Target=\"worksheets/a.xml\" ${if (external) "TargetMode=\"External\"" else ""}/><Relationship Id=\"b\" Target=\"/xl/worksheets/b.xml\"/></Relationships>",
            "xl/sharedStrings.xml" to "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><si><r><t>P</t></r><r><t>1</t></r></si></sst>",
            "xl/worksheets/a.xml" to sheet(listOf("Payload ID", "挿入位置", "最小tier", "Payload原文（JSON文字列表記）", "適用文脈", "分類", "観測・追加確認", "適用注意"), listOf("P1", "replace", "light", "\"日<&\"", "query, form", "SQL", "contrast", "observe")),
            "xl/worksheets/b.xml" to sheet(listOf("モード", "識別名", "Grep match文字列（正規表現）"), listOf("replace", "g", "error.*"))
        )
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip -> data.forEach { (name, value) -> zip.putNextEntry(ZipEntry(name)); zip.write(value.toByteArray(Charsets.UTF_8)); zip.closeEntry() } }
        return out.toByteArray()
    }
    @Test fun `shared rich strings and inline unicode preserve literal payload content`() {
        val bytes = fixture()
        val result = readPayloadWorkbook(bytes)
        assertEquals(ProfilePayload("P1", "replace", "light", "日<&", listOf("query", "form"), "SQL", "contrast", "observe"), result.payloads.single())
        assertEquals(ProfileGrep("replace", "g", "error.*"), result.grep.single())
        assertEquals(sha256(bytes), result.workbookSha256)
    }
    @Test fun `formula cells and external sheet relationships are refused`() {
        assertThrows(IllegalArgumentException::class.java) { readPayloadWorkbook(fixture(formula = true)) }
        assertThrows(IllegalArgumentException::class.java) { readPayloadWorkbook(fixture(external = true)) }
    }
    @Test fun `doctype is refused without external entity resolution`() {
        assertThrows(org.xml.sax.SAXParseException::class.java) { readPayloadWorkbook(fixture(dtd = true)) }
    }
}
