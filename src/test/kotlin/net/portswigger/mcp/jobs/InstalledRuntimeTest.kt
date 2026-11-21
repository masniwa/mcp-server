package net.portswigger.mcp.jobs

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class InstalledRuntimeTest {
    @TempDir lateinit var root:Path
    @Test fun `loading an installed re jar creates a stable authenticated profile without environment variables`() {
        val first=ManagedSettings.forExtension(emptyMap(),root)
        val second=ManagedSettings.forExtension(emptyMap(),root)
        assertTrue(first.enabled);assertEquals(first.workerToken,second.workerToken);assertEquals(first.cphToken,second.cphToken)
        assertNotEquals(first.workerToken,first.cphToken);assertTrue(first.workerToken!!.length>=32)
        assertEquals(root.resolve("runtime/worker-store"),first.directory)
        assertEquals(listOf(root.resolve("runtime/jobs")),first.inputRoots)
        assertTrue(first.capabilities.isEmpty());assertTrue(first.authorized("Bearer ${first.workerToken}"))
        assertFalse(first.authorized(null));assertTrue(Files.exists(root.resolve("runtime/settings.json")))
        assertEquals(InstalledRuntime.defaultAuthorizationMode()=="QUICK",first.quick)
    }
    @Test fun `explicit compatibility environment remains available and does not create a profile`() {
        assertFalse(ManagedSettings.forExtension(mapOf("BURP_DIAG_MANAGED" to "0"),root).enabled)
        assertFalse(Files.exists(root.resolve("runtime")))
    }
    @Test fun `malformed existing secrets fail closed rather than downgrade or replace credentials`() {
        ManagedSettings.forExtension(emptyMap(),root)
        val secrets=root.resolve("runtime/operator-secrets.json");Files.writeString(secrets,"{}")
        assertThrows(Exception::class.java) { ManagedSettings.forExtension(emptyMap(),root) }
        assertEquals("{}",Files.readString(secrets))
    }
    @Test fun `profile storage cannot escape the installation runtime directory`() {
        ManagedSettings.forExtension(emptyMap(),root)
        Files.writeString(root.resolve("runtime/settings.json"),"""{"schemaVersion":1,"workerStore":"../../elsewhere"}""")
        assertThrows(Exception::class.java) { ManagedSettings.forExtension(emptyMap(),root) }
        assertFalse(Files.exists(root.parent.resolve("elsewhere")))
    }
    @Test fun `jar location controls paths independently of the working directory`() {
        assertEquals(root,InstalledRuntime.rootForJar(root.resolve("build/libs/burp-mcp-all.jar")))
        assertEquals(root.resolve("deployment"),InstalledRuntime.rootForJar(root.resolve("deployment/server.jar")))
    }
    @Test fun `authorization mode comes from operator profile and invalid modes fail closed`() {
        ManagedSettings.forExtension(emptyMap(),root)
        val file=root.resolve("runtime/settings.json")
        val initial=Files.readString(file)
        val selected=kotlinx.serialization.json.Json.parseToJsonElement(initial).let {
            val values=(it as kotlinx.serialization.json.JsonObject).toMutableMap()
            values["authorizationMode"]=kotlinx.serialization.json.JsonPrimitive("QUICK")
            kotlinx.serialization.json.JsonObject(values).toString()
        }
        Files.writeString(file,selected);assertTrue(ManagedSettings.forExtension(emptyMap(),root).quick)
        Files.writeString(file,selected.replace("QUICK","UNKNOWN"))
        assertThrows(Exception::class.java) { ManagedSettings.forExtension(emptyMap(),root) }
    }
}
