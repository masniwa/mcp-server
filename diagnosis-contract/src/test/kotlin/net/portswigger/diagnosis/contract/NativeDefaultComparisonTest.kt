package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeDefaultComparisonTest {
    private fun project(index:Int?,mode:String="derive_from_prior_response"):JsonObject = buildJsonObject {
        putJsonObject("project_options") { putJsonObject("sessions") { putJsonObject("macros") { putJsonArray("macros") { add(buildJsonObject {
            put("serial_number",9007199254740993L);putJsonArray("items") { add(buildJsonObject { putJsonArray("request_parameters") { add(buildJsonObject {
                put("name","token");put("parameter_handling",mode);index?.let { put("prior_response_index",it) }
            }) } }) }
        }) } } } }
    }
    @Test fun `derive index zero omission equals only its observed native default and preserves source`() {
        val explicit=project(0);val omitted=project(null)
        assertEquals(projectDefinitions(explicit),projectDefinitions(omitted))
        assertNotEquals(explicit,omitted)
        assertTrue(explicit.toString().contains("9007199254740993"));assertTrue(explicit.toString().contains("prior_response_index"))
    }
    @Test fun `nonzero references and unrelated parameter modes are never ignored`() {
        assertNotEquals(projectDefinitions(project(1)),projectDefinitions(project(null)))
        assertNotEquals(projectDefinitions(project(0,"preset_value")),projectDefinitions(project(null,"preset_value")))
    }
}
