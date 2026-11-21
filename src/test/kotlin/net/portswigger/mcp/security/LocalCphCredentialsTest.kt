package net.portswigger.mcp.security

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class LocalCphCredentialsTest {
    @TempDir lateinit var root:Path
    private fun secrets(directory:Path):Path {
        Files.createDirectories(directory)
        Files.writeString(directory.resolve("operator-secrets.json"),"""{"cph":"${"c".repeat(48)}"}""")
        return directory
    }
    @Test fun `legacy installation without profile keeps unauthenticated CPH behavior`() {
        assertNull(LocalCphCredentials.authorization("127.0.0.1",17866,root))
    }
    @Test fun `same local credentials work for either installation selected by the user`() {
        secrets(root.resolve("re/runtime"))
        val legacy=root.resolve("legacy/runtime");Files.createDirectories(legacy)
        Files.writeString(legacy.resolve("cph-connection.json"),"""{"runtimeDirectory":"../../re/runtime"}""")
        assertEquals("Bearer ${"c".repeat(48)}",LocalCphCredentials.authorization("127.0.0.1",17866,root.resolve("legacy")))
        assertEquals("Bearer ${"c".repeat(48)}",LocalCphCredentials.authorization("127.0.0.1",17866,root.resolve("re")))
    }
    @Test fun `credentials are never supplied for remote or different local services`() {
        secrets(root.resolve("runtime"))
        assertNull(LocalCphCredentials.authorization("attacker.invalid",17866,root))
        assertNull(LocalCphCredentials.authorization("127.0.0.1",18084,root))
    }
    @Test fun `invalid local profile is not silently bypassed`() {
        val directory=secrets(root.resolve("runtime"));Files.writeString(directory.resolve("operator-secrets.json"),"{}")
        assertEquals("CPH_LOCAL_CREDENTIALS_INVALID",assertThrows(IllegalStateException::class.java) { LocalCphCredentials.authorization("127.0.0.1",17866,root) }.message)
    }
}
