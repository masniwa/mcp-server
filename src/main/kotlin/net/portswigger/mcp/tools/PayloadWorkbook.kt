package net.portswigger.mcp.tools

import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.w3c.dom.Node
import kotlinx.serialization.json.Json

/** Read-only OOXML import. No formulas, external relationships, macros or XML entities execute. */
internal fun readPayloadWorkbook(bytes: ByteArray): PayloadProfileCatalog {
    val entries = mutableMapOf<String, ByteArray>()
    var total = 0L
    ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
        while (true) {
            val entry = zip.nextEntry ?: break
            if (!entry.isDirectory && (entry.name.endsWith(".xml") || entry.name.endsWith(".rels"))) {
                val content = zip.readNBytes(32 * 1024 * 1024 + 1)
                require(content.size <= 32 * 1024 * 1024) { "Workbook XML entry too large" }
                total += content.size
                require(total <= 128 * 1024 * 1024 && entries.size < 1024) { "Workbook XML exceeds import limits" }
                require(entries.put(entry.name, content) == null) { "Duplicate workbook ZIP entry" }
            }
            zip.closeEntry()
        }
    }
    fun xml(path: String): Element {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
        return factory.newDocumentBuilder().parse(ByteArrayInputStream(requireNotNull(entries[path]) { "Missing workbook entry: $path" })).documentElement
    }
    val shared = if (entries.containsKey("xl/sharedStrings.xml")) xml("xl/sharedStrings.xml").children("si").map { it.textParts() } else emptyList()
    val relationships = xml("xl/_rels/workbook.xml.rels").children("Relationship").associate { e ->
        require(e.getAttribute("TargetMode") != "External") { "External workbook relationship refused" }
        e.getAttribute("Id") to e.getAttribute("Target")
    }
    val workbook = xml("xl/workbook.xml")
    fun rows(name: String, required: List<String>): List<Map<String, String>> {
        val sheet = workbook.children("sheets").single().children("sheet").filter { it.getAttribute("name") == name }.single()
        val id = sheet.getAttributeNS("http://schemas.openxmlformats.org/officeDocument/2006/relationships", "id")
        val target = requireNotNull(relationships[id]) { "Missing sheet relationship" }
        val path = if (target.startsWith('/')) target.removePrefix("/") else "xl/$target"
        require(!path.split('/').contains("..")) { "Nonlocal sheet relationship" }
        val data = xml(path).children("sheetData").single().children("row")
        fun cells(row: Element): Map<String, String> = row.children("c").associate { c ->
            require(c.children("f").isEmpty() && c.getAttribute("t") != "e") { "Formula/error cell in $name" }
            val column = c.getAttribute("r").takeWhile { it in 'A'..'Z' }
            val value = when (c.getAttribute("t")) {
                "inlineStr" -> c.children("is").single().textParts()
                "s" -> shared[c.children("v").single().textContent.toInt()]
                "str" -> c.children("v").singleOrNull()?.textContent ?: ""
                else -> {
                    c.children("v").singleOrNull()?.textContent ?: ""
                }
            }
            column to value
        }
        val header = cells(data.single { it.getAttribute("r") == "5" })
        require(header.values.filter { it.isNotEmpty() }.distinct().size == header.values.count { it.isNotEmpty() }) { "Duplicate headers in $name" }
        require(header.values.containsAll(required)) { "Missing headers in $name" }
        return data.filter { it.getAttribute("r").toInt() >= 6 }.mapNotNull { row ->
            val values = cells(row)
            if (values.values.all { it.isEmpty() }) null else required.associateWith { field ->
                val column = header.entries.single { it.value == field }.key
                val cell = row.children("c").single { it.getAttribute("r").takeWhile { c -> c in 'A'..'Z' } == column }
                require(cell.getAttribute("t") in setOf("s", "str", "inlineStr")) { "Expected literal text for $field in $name" }
                requireNotNull(values[column]) { "Missing $field in $name" }
            }
        }
    }
    val payloads = rows("Payloads", listOf("Payload ID", "挿入位置", "最小tier", "Payload原文（JSON文字列表記）", "適用文脈", "分類", "観測・追加確認", "適用注意")).map { r ->
        ProfilePayload(r.getValue("Payload ID"), r.getValue("挿入位置"), r.getValue("最小tier"),
            Json.decodeFromString<String>(r.getValue("Payload原文（JSON文字列表記）")), r.getValue("適用文脈").split(',').map { it.trim() },
            r.getValue("分類"), r.getValue("観測・追加確認"), r.getValue("適用注意"))
    }
    val grep = rows("Grep match", listOf("モード", "識別名", "Grep match文字列（正規表現）")).map { r ->
        ProfileGrep(r.getValue("モード"), r.getValue("識別名"), r.getValue("Grep match文字列（正規表現）"))
    }
    return PayloadProfileCatalog(sha256(bytes), payloads, grep).also { it.validate() }
}

private fun Node.children(name: String): List<Element> = (0 until childNodes.length).map { childNodes.item(it) }
    .filterIsInstance<Element>().filter { it.localName == name }

private fun Element.textParts(): String {
    val nodes = getElementsByTagNameNS("*", "t")
    return (0 until nodes.length).joinToString("") { nodes.item(it).textContent }
}
