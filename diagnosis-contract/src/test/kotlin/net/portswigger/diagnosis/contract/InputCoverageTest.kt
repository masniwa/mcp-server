package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class InputCoverageTest {
    private val four=listOf(InputParameter("loggedout","URL"),InputParameter("csrfmiddlewaretoken","BODY"),InputParameter("login","BODY"),InputParameter("password","BODY"))
    private fun options(parameters:List<InputParameter>)=buildJsonObject { put("insertionPointParameters",jobJson.encodeToJsonElement(parameters)) }
    private fun rejection(code:String,block:()->Unit) { assertEquals(code,assertThrows(JobRejected::class.java,block).code) }
    private fun macro(mode:String="specified",names:List<String> = listOf("csrfmiddlewaretoken"),update:Boolean=true)=buildJsonObject {
        put("type","run_macro");put("enabled",true);put("update_with_params",update);put("match_params",mode)
        putJsonArray("specified_params") { names.forEach { add(it) } }
    }
    @Test fun `four observed parameters cannot become three selected parameters silently`() {
        val selected=four.filterNot { it.name=="csrfmiddlewaretoken" }
        rejection("INPUT_EXCLUSION_REQUIRED") { InputCoverage.validateInventory(options(selected),emptyList(),four) }
        val declared=listOf(InputExclusion("csrfmiddlewaretoken","BODY","User reviewed the untested token input; it needs separate diagnosis"))
        InputCoverage.validateInventory(options(selected),declared,four)
        assertEquals(listOf("csrfmiddlewaretoken"),declared.map { it.name })
        assertTrue(jobJson.encodeToJsonElement(declared).toString().contains("separate diagnosis"))
    }
    @Test fun `four selected inputs cannot be repaired over their attacks by a prerequisite Macro`() {
        rejection("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { InputCoverage.validateMacroPreservation(options(four),listOf(macro())) }
        val selected=four.filterNot { it.name=="csrfmiddlewaretoken" }
        InputCoverage.validateMacroPreservation(options(selected),listOf(macro()))
        InputCoverage.validateMacroPreservation(options(four),listOf(macro(update=false)))
    }
    @Test fun `native identity preserves exact case type and distinct locations with all occurrences`() {
        val native=listOf(InputParameter("state","URL"),InputParameter("state","BODY"),InputParameter("State","BODY"),InputParameter("state","BODY"))
        val selected=listOf(InputParameter("state","BODY"))
        val excluded=listOf(InputExclusion("state","URL","Reviewed query exclusion"),InputExclusion("State","BODY","Reviewed case-distinct exclusion"))
        InputCoverage.validateInventory(options(selected),excluded,native)
        rejection("SELECTED_INPUT_NOT_FOUND") { InputCoverage.validateInventory(options(listOf(InputParameter("state","body"))),excluded,native) }
        rejection("INPUT_EXCLUSION_REQUIRED") { InputCoverage.validateInventory(options(selected),excluded.take(1),native) }
        // Native Macro updates have no type discriminator; another location with the same name still conflicts.
        rejection("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { InputCoverage.validateMacroPreservation(options(selected),listOf(macro(names=listOf("state")))) }
        InputCoverage.validateMacroPreservation(options(selected),listOf(macro(names=listOf("State"))))
    }
    @Test fun `conditional recovery Macro is checked even when normal prerequisite is safe`() {
        val recovery=buildJsonObject {
            put("type","validate_session");put("enabled",true);put("perform_action_if_invalid",true);put("action","run_macro")
            put("run_macro_action",macro(names=listOf("password")))
        }
        rejection("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { InputCoverage.validateMacroPreservation(options(four),listOf(macro(update=false),recovery)) }
        InputCoverage.validateMacroPreservation(options(four),listOf(JsonObject(recovery+("perform_action_if_invalid" to JsonPrimitive(false)))))
        InputCoverage.validateMacroPreservation(options(four),listOf(JsonObject(recovery+("enabled" to JsonPrimitive(false)))))
    }
    @Test fun `all except must protect every selected name and unknown update modes fail closed`() {
        InputCoverage.validateMacroPreservation(options(four),listOf(macro("all_except",four.map { it.name })))
        rejection("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { InputCoverage.validateMacroPreservation(options(four),listOf(macro("all_except",listOf("login","password")))) }
        rejection("MACRO_INPUT_UPDATE_UNSPECIFIED") { InputCoverage.validateMacroPreservation(options(four),listOf(macro("future_mode"))) }
        rejection("MACRO_INPUT_UPDATE_UNSPECIFIED") { InputCoverage.validateMacroPreservation(options(four),listOf(JsonObject(macro()-"update_with_params"))) }
    }
    @Test fun `declarations cannot name nonexistent selected duplicate or unexplained omissions`() {
        val selected=options(four.take(1))
        val exclusion=InputExclusion("password","BODY","Reviewed password exclusion")
        rejection("INPUT_EXCLUSION_REASON_REQUIRED") { InputCoverage.validateDeclarations(selected,listOf(exclusion.copy(reason=" "))) }
        InputCoverage.validateDeclarations(selected,listOf(exclusion.copy(reason="r".repeat(1000))))
        rejection("INPUT_EXCLUSION_REASON_REQUIRED") { InputCoverage.validateDeclarations(selected,listOf(exclusion.copy(reason="r".repeat(1001)))) }
        rejection("DUPLICATE_INPUT_EXCLUSION") { InputCoverage.validateDeclarations(selected,listOf(exclusion,exclusion)) }
        rejection("SELECTED_INPUT_EXCLUDED") { InputCoverage.validateDeclarations(options(four),listOf(exclusion)) }
        rejection("EXCLUDED_INPUT_NOT_FOUND") { InputCoverage.validateInventory(options(four),listOf(exclusion.copy(name="invented")),four) }
        rejection("INPUT_EXCLUSIONS_REQUIRE_SELECTION") { InputCoverage.validateDeclarations(JsonObject(emptyMap()),listOf(exclusion)) }
        rejection("DUPLICATE_INPUT_SELECTION") { InputCoverage.selected(options(listOf(four.first(),four.first()))) }
    }
    @Test fun `automatic native selectors remain untouched without a new exclusion claim`() {
        val automatic=JsonObject(emptyMap())
        InputCoverage.validateDeclarations(automatic,emptyList())
        InputCoverage.validateInventory(automatic,emptyList(),four)
        InputCoverage.validateMacroPreservation(automatic,listOf(macro()))
        assertNull(InputCoverage.selected(automatic))
    }
}
