package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeProjectReadbackTest {
    private fun project(prefix:String,enabled:Boolean=true)=buildJsonObject {
        putJsonObject("project_options") { putJsonObject("sessions") {
            putJsonObject("session_handling_rules") { putJsonArray("rules") {
                add(buildJsonObject {
                    put("description","job:sample:session");put("enabled",enabled)
                    put("url_scope_advanced_mode",false)
                    putJsonArray("include_in_scope") { add(buildJsonObject {
                        put("enabled",true);put("include_subdomains",false);put("prefix",prefix)
                    }) }
                    put("exclude_from_scope",JsonArray(emptyList()))
                })
            } }
        } }
    }

    @Test fun `native lowercased query prefix preserves guarded comparison`() {
        val planned=project("https://fixture.invalid/api.php?_r=mlDeliveryList")
        val native=project("https://fixture.invalid/api.php?_r=mldeliverylist")
        assertTrue(projectNativeScopeEquivalent(planned,native))
        assertFalse(projectNativeScopeEquivalent(planned,project("https://fixture.invalid/api.php?_r=other")))
        assertFalse(projectNativeScopeEquivalent(planned,project("https://fixture.invalid/API.php?_r=mldeliverylist")))
        assertFalse(projectNativeScopeEquivalent(planned,project("https://fixture.invalid/api.php?_r=mldeliverylist",false)))
    }
}
