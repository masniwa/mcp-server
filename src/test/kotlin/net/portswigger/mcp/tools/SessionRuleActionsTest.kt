package net.portswigger.mcp.tools

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SessionRuleActionsTest {
    @Test fun `macro validation keeps later actions and exact large references`() {
        val id = 9_007_199_254_740_993L
        val action = GenerateSessionValidationAction("signed-in", validationMacroSerialNumber=id, recoveryMacroSerialNumber=id+1).toAction()
        assertEquals(id, action.getValue("macro_serial_number").jsonPrimitive.long)
        assertFalse(action.getValue("stop_if_valid").jsonPrimitive.boolean)
        assertTrue(action.getValue("perform_action_if_invalid").jsonPrimitive.boolean)
        val recovery = action.getValue("run_macro_action").jsonObject
        assertEquals(id+1, recovery.getValue("macro_serial_number").jsonPrimitive.long)
        assertFalse(recovery.getValue("update_with_params").jsonPrimitive.boolean)
        assertEquals(JsonArray(emptyList()), recovery.getValue("specified_params"))
    }
    @Test fun `only specified state parameters are updated`() {
        val action = GenerateSessionValidationAction("signed-in", validationMacroSerialNumber=1, recoveryMacroSerialNumber=2, recoveryParameterNames=listOf("state")).toAction()
        assertEquals(JsonArray(listOf(JsonPrimitive("state"))), action["run_macro_action"]!!.jsonObject["specified_params"])
    }
    @Test fun `current request requires verified repeatability and stops further actions`() {
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("ok", validationAction="issue_current_request").toAction() }
        assertTrue(GenerateSessionValidationAction("ok", validationAction="issue_current_request", currentRequestIsSafeAndRepeatable=true).toAction()["stop_if_valid"]!!.jsonPrimitive.boolean)
    }
    @Test fun `invalid criteria and references are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("", validationMacroSerialNumber=1).toAction() }
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("ok").toAction() }
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("ok", validationMacroSerialNumber=1, requestCount=0).toAction() }
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("ok", validationMacroSerialNumber=1, inspectResponseBody=false).toAction() }
        assertThrows(IllegalArgumentException::class.java) { GenerateSessionValidationAction("[", validationMacroSerialNumber=1, matchType="regex").toAction() }
    }
    @Test fun `no recovery does not claim recovery is enabled`() {
        val action=GenerateSessionValidationAction("ok", validationMacroSerialNumber=1).toAction()
        assertFalse(action["perform_action_if_invalid"]!!.jsonPrimitive.boolean)
        assertFalse(action["run_macro_action"]!!.jsonObject.containsKey("macro_serial_number"))
    }
    @Test fun `extension action uses exact registered name`() {
        val action=GenerateInvokeExtensionAction("Randomizer").toAction()
        assertEquals("invoke_extension",action["type"]!!.jsonPrimitive.content)
        assertEquals("Randomizer",action["action_name"]!!.jsonPrimitive.content)
        assertThrows(IllegalArgumentException::class.java) { GenerateInvokeExtensionAction(" ").toAction() }
    }
}
