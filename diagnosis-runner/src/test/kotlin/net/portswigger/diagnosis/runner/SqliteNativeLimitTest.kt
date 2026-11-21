package net.portswigger.diagnosis.runner

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.sql.DriverManager
import java.sql.SQLException
import kotlinx.serialization.json.*

class SqliteNativeLimitTest {
    @Test fun defaultNativeScalarLimitRejectsOversizeWithoutAllocatingTheRequestedBlob() {
        Class.forName("org.sqlite.JDBC")
        DriverManager.getConnection("jdbc:sqlite::memory:").use { db ->
            val limit=(db as org.sqlite.SQLiteConnection).database.limit(org.sqlite.SQLiteLimits.SQLITE_LIMIT_LENGTH.id,-1).toLong()
            val fixture=javaClass.getResourceAsStream("/anonymous-large-issue-sizes.json")!!.bufferedReader().use { Json.parseToJsonElement(it.readText()).jsonObject }
            val sizes=fixture.getValue("jsonStringUtf8Bytes").jsonArray.map { it.jsonPrimitive.long }
            // Original collection puts both issues in one JSON-string page, separated by two newlines.
            val legacyPageBytes=sizes.sumOf { it-2 }+4*(sizes.size-1)+2
            assertTrue(legacyPageBytes>limit)
            val failure=assertThrows(SQLException::class.java) {
                db.createStatement().use { it.executeQuery("SELECT zeroblob($legacyPageBytes)").use { rows -> rows.next() } }
            }
            assertEquals(18,failure.errorCode and 255)
            println("SQLITE_DEFAULT_MAX_LENGTH=$limit; ANONYMOUS_LEGACY_PAGE_BYTES=$legacyPageBytes; OVERSIZE_PRIMARY_CODE=${failure.errorCode and 255}")
        }
    }
}
