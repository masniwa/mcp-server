package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeMacroReferencesTest {
    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    @Test fun currentRequestValidationIgnoresUnusedValidationMacroButKeepsRecoveryAndUnknownModes() {
        val action=obj("""{"type":"validate_session","validation_action":"issue_current_request","macro_serial_number":1,"run_macro_action":{"macro_serial_number":2}}""")
        assertEquals(setOf(JsonPrimitive(2)),nativeMacroReferences(action))
        val unknown=JsonObject(action+("validation_action" to JsonPrimitive("future_mode")))
        assertEquals(setOf(JsonPrimitive(1),JsonPrimitive(2)),nativeMacroReferences(unknown))
    }
    @Test fun explicitlyInactiveKnownActionsAndRecoveryBranchesDoNotCreateDependencies() {
        for(type in listOf("run_macro","run_post_request_macro","validate_session","invoke_extension"))
            assertTrue(nativeMacroReferences(obj("""{"type":"$type","enabled":false,"macro_serial_number":1}""")).isEmpty())
        val rule=obj("""{"type":"validate_session","macro_serial_number":1,"perform_action_if_invalid":false,"run_macro_action":{"macro_serial_number":2}}""")
        assertEquals(setOf(JsonPrimitive(1)),nativeMacroReferences(rule))
    }
    @Test fun activeUnknownAndMissingFlagsRetainExactSerialsAndNestedReferences() {
        for(flags in listOf("",",\"enabled\":true",",\"enabled\":\"false\""))
            assertEquals(setOf(JsonPrimitive(9007199254740993L)),nativeMacroReferences(obj("""{"type":"run_macro","macro_serial_number":9007199254740993$flags}""")))
        assertEquals(setOf(JsonPrimitive(2)),nativeMacroReferences(obj("""{"type":"future_action","enabled":false,"nested":{"macro_serial_number":2}}""")))
        assertEquals(setOf(JsonPrimitive(1),JsonPrimitive(2)),nativeMacroReferences(obj("""{"type":"validate_session","macro_serial_number":1,"run_macro_action":{"macro_serial_number":2}}""")))
    }
}
