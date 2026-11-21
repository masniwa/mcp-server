package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Path
import java.nio.file.Files
import java.security.MessageDigest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class PayloadProfileTest {
    @TempDir lateinit var temporary: Path
    private val hash = "a".repeat(64)
    private fun catalog() = PayloadProfileCatalog(hash, PAYLOAD_TIERS.flatMap { tier ->
        PAYLOAD_MODES.map { mode -> ProfilePayload("$tier-$mode", mode, tier, "same", listOf("query")) }
    })

    @Test fun `tiers are cumulative and each row keeps its own mode`() {
        val source = catalog()
        assertEquals(3, source.select("light").size)
        val medium = source.select("medium")
        assertEquals(6, medium.size)
        assertEquals(9, source.select("hard").size)
        assertEquals(setOf("light", "medium"), medium.map { it.minimumTier }.toSet())
        assertEquals(PAYLOAD_MODES.associateWith { 2 }, medium.groupingBy { it.mode }.eachCount())
        assertEquals(medium.map { it.id }.toSet().size, medium.size)
    }

    @Test fun `explicit mode restricts selection but equal values keep distinct IDs`() {
        assertEquals(listOf("light-array", "medium-array"), catalog().select("medium", listOf("array")).map { it.id })
        assertEquals(6, catalog().select("medium").count { it.raw == "same" })
    }

    @Test fun `unknown empty and duplicate modes never fall back to all`() {
        for (modes in listOf(emptyList(), listOf("replace", "replace"), listOf("typo"))) {
            assertThrows(IllegalArgumentException::class.java) { catalog().select("medium", modes) }
        }
        assertThrows(IllegalArgumentException::class.java) { catalog().select("Medeium") }
    }

    @Test fun `invalid definitions including unselected rows fail before selection`() {
        val base = catalog()
        val last = base.payloads.last()
        val invalid = listOf(
            base.copy(workbookSha256 = "unknown"), base.copy(payloads = emptyList()),
            base.copy(payloads = base.payloads + last),
            base.copy(payloads = base.payloads + last.copy(id = "bad", mode = "unknown")),
            base.copy(payloads = base.payloads + last.copy(id = "bad", minimumTier = "unknown")),
            base.copy(payloads = base.payloads + last.copy(id = "bad", contexts = listOf("unknown")))
        )
        invalid.forEach { source -> assertThrows(IllegalArgumentException::class.java) { source.select("light") } }
    }

    @Test fun `unbound payload remains identifiable without a substituted send value`() {
        val p = ProfilePayload("p", "replace", "light", "__HOST__/__PATH__/__HOST__", listOf("query"))
        val result = bindProfilePayload(p, mapOf("__HOST__" to "example.test"))
        assertEquals("p", result.payloadId)
        assertNull(result.raw)
        assertEquals(listOf("__PATH__"), result.missingBindings)
    }

    @Test fun `bindings are literal single pass and preserve payload lexemes`() {
        val p = ProfilePayload("p", "replace", "light", "__A__ __B__ -0 1e309", listOf("raw"))
        val result = bindProfilePayload(p, mapOf("__A__" to "__B__", "__B__" to "$\\x"))
        assertEquals("__B__ $\\x -0 1e309", result.raw)
        assertTrue(result.missingBindings.isEmpty())
    }

    @Test fun `source byte changes reject a stale catalog`() {
        val workbook = temporary.resolve("source.xlsx")
        val exported = temporary.resolve("catalog.json")
        val original = "source bytes".toByteArray()
        Files.write(workbook, original)
        val digest = MessageDigest.getInstance("SHA-256").digest(original).joinToString("") { "%02x".format(it.toInt() and 255) }
        Files.writeString(exported, Json.encodeToString(catalog().copy(workbookSha256 = digest)))
        assertThrows(IllegalArgumentException::class.java) { loadPayloadProfile(exported, workbook) } // Not an XLSX, despite a matching digest.
        Files.writeString(workbook, "changed")
        assertThrows(IllegalArgumentException::class.java) { loadPayloadProfile(exported, workbook) }
    }

    @Test fun `invalid or duplicate grep definitions fail before scan`() {
        for (grep in listOf(listOf(ProfileGrep("append", "g", "[")),
            List(2) { ProfileGrep("append", "g", "error") }, listOf(ProfileGrep("unknown", "g", "error")))) {
            assertThrows(IllegalArgumentException::class.java) { catalog().copy(grep = grep).validate() }
        }
    }

    @Test fun `exported workbook catalog loads in Kotlin with expected cumulative tiers`() {
        val source = System.getenv("PAYLOAD_TEST_WORKBOOK")
        val exported = System.getenv("PAYLOAD_TEST_CATALOG")
        assumeTrue(source != null && exported != null, "Requires the explicit workbook integration fixture")
        val loaded = loadPayloadProfile(Path.of(exported), Path.of(source))
        assertEquals(670, loaded.payloads.size)
        assertEquals(23, loaded.grep.size)
        assertEquals(mapOf("append" to 184, "replace" to 254, "array" to 20),
            loaded.select("medium").groupingBy { it.mode }.eachCount())
        assertEquals(162, loaded.select("light").size)
        assertEquals(670, loaded.select("hard").size)
        val tampered = temporary.resolve("tampered.json")
        Files.writeString(tampered, Json.encodeToString(loaded.copy(payloads = loaded.payloads.drop(1))))
        assertThrows(IllegalArgumentException::class.java) { loadPayloadProfile(tampered, Path.of(source)) }
    }
}
