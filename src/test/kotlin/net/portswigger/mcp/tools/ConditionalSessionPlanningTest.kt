package net.portswigger.mcp.tools

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** In-memory planning boundary tests, not an emulator of Burp's native session executor. */
class ConditionalSessionPlanningTest {
    private val caps = setOf("SCANNER_WORKFLOW", "EXCLUSIVE_CONTEXT", "DYNAMIC_WORKFLOW_VERIFIED")
    private val root = Endpoint("http", "fixture.invalid", 8080, "/")
    private fun material(id: String, path: String, method: String = "GET", body: String = ""): HttpMaterial {
        val request = "$method $path HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n$body"
        val response = "HTTP/1.1 200 OK\r\n\r\n$id"
        return HttpMaterial(id, root.copy(path = path), request, response, digest(request), digest(response))
    }
    private val target = material("target", "/items", "POST", "title=attack-value&csrf=marker")
    private val probe = material("probe", "/protected")
    private val login = material("login", "/login", "POST", "username=tester&password=fixture")
    private val form = material("form", "/form")
    private val saved = material("saved", "/items")
    private val logout = material("logout", "/logout")
    private val validationSerial = 9_007_199_254_740_993L
    private val recoverySerial = validationSerial + 1
    private val preparationSerial = validationSerial + 2
    private val storedSerial = validationSerial + 3
    private val baseline = BurpSnapshot("mock-instance", jobJson.parseToJsonElement("""
        {"project_options":{"sessions":{"macros":{"macros":[]},"session_handling_rules":{"rules":[]}},
        "resource_pools":{"default_resource_pool":{"concurrent_request_limit_enabled":true,"concurrent_request_limit":10}}}}
    """).jsonObject, JsonObject(emptyMap()), emptyList(), caps)

    private fun macro(id: Long, source: HttpMaterial) = buildJsonObject {
        put("description", "job:conditional:${source.id}"); put("serial_number", id)
        putJsonArray("items") { add(buildJsonObject {
            put("url", source.endpoint.url()); put("request", source.request); put("response", source.response)
            put("method", source.request.substringBefore(' ')); put("status_code", 200)
            put("accept_response_cookies", true); put("use_request_cookies", true)
            put("custom_parameters", JsonArray(emptyList())); put("request_parameters", JsonArray(emptyList()))
        }) }
    }
    private fun action() = GenerateSessionValidationAction(
        "probe", validationMacroSerialNumber = validationSerial, recoveryMacroSerialNumber = recoverySerial,
        recoveryParameterNames = listOf("csrf")
    ).toAction()
    private fun runMacro(id: Long) = buildJsonObject {
        put("type", "run_macro"); put("enabled", true); put("macro_serial_number", id)
        put("invoke_extension_action", false); put("match_cookies", "all_except")
        put("match_params", "specified"); put("specified_params", JsonArray(listOf(JsonPrimitive("csrf"))))
        put("tolerate_url_mismatch", false); put("update_with_cookies", true); put("update_with_params", true)
    }
    private fun settings(stored: Boolean = false): SettingsPlan {
        val actions = mutableListOf<JsonElement>(action(), runMacro(preparationSerial))
        if (stored) actions += buildJsonObject {
            put("type", "run_post_request_macro"); put("enabled", true); put("macro_serial_number", storedSerial)
            put("pass_back", "final_response"); put("match_params", "specified")
            put("specified_params", JsonArray(emptyList())); put("update_with_params", false)
        }
        val rule = buildJsonObject {
            put("description", "job:conditional:${if (stored) "stored" else "reflection"}"); put("enabled", true)
            put("actions", JsonArray(actions)); put("exclude_from_scope", JsonArray(emptyList()))
            put("named_params", JsonArray(emptyList())); put("restrict_scope_to_named_params", false)
            put("tools_scope", JsonArray(listOf(JsonPrimitive("Scanner"), JsonPrimitive("Extensions"))))
            put("url_scope", "custom"); put("url_scope_advanced_mode", false)
            putJsonArray("include_in_scope") { add(buildJsonObject {
                put("enabled", true); put("include_subdomains", false); put("prefix", target.endpoint.url())
            }) }
        }
        // Minimal compiler fixture: verifies definition preservation, not native CPH execution.
        val cph = buildJsonObject { putJsonObject("job:conditional:current-form") {
            put("enabled", true); put("dynamic_checkbox", true); put("extract_choice_index", 0)
            put("single_request", form.request); put("single_response", form.response)
            putJsonArray("issuer") { add(false); add(root.host); add(root.port) }
        } }
        val macros = listOf(macro(validationSerial, probe), macro(recoverySerial, login), macro(preparationSerial, form)) +
            if (stored) listOf(macro(storedSerial, saved)) else emptyList()
        return SettingsPlan(macros = JsonArray(macros), rules = JsonArray(listOf(rule)), cph = cph,
            cphOrder = cph.keys.toList(), serialScannerRequests = true)
    }
    private fun request(source: HttpMaterial) = RequestPlan(source.endpoint, source.request, source.id, source.requestSha256)
    private fun proposal(stored: Boolean = false): JobProposal {
        fun variant(id: String, kind: String, settings: SettingsPlan, verification: String? = null) = ScanVariant(
            id, kind, verification, request(target), settings, listOf("normal", "expired-session"),
            mapOf("expired-session" to listOf(request(logout)))
        )
        val variants = listOf(variant("reflection", "REFLECTION", settings())) +
            if (stored) listOf(variant("stored", "STORED", settings(true), saved.id)) else emptyList()
        return JobProposal(jobId = "conditional", revision = 1, objective = "Reuse the owned session with conditional recovery",
            targetPolicy = listOf(TargetPermit(root, pathPrefix = true)), materials = listOf(target, probe, login, form, saved, logout),
            session = SessionPlan(true, "USE", "Observed safe protected probe and recovery login", "mock-owned-account", validationSourceId = probe.id),
            variants = variants, storedVerificationSourceIds = if (stored) listOf(saved.id) else emptyList(),
            requiredCapabilities = caps, cleanupPolicy = "Separate approved final owned-session cleanup after controls")
    }
    private fun compiledActions(v: CompiledVariant) = v.project["project_options"]!!.jsonObject["sessions"]!!.jsonObject[
        "session_handling_rules"]!!.jsonObject["rules"]!!.jsonArray.single().jsonObject["actions"]!!.jsonArray

    @Test fun `generated conditional action compiles without unconditional login and preserves fresh preparation`() {
        val proposal = proposal()
        val variant = JobCompiler().compile(proposal, baseline).variants.single()
        val actions = compiledActions(variant)
        assertEquals(action(), actions.first())
        assertFalse(actions.first().jsonObject["stop_if_valid"]!!.jsonPrimitive.boolean)
        assertEquals(recoverySerial, actions.first().jsonObject["run_macro_action"]!!.jsonObject["macro_serial_number"]!!.jsonPrimitive.long)
        assertEquals(listOf(preparationSerial), actions.filter { it.jsonObject["type"]!!.jsonPrimitive.content == "run_macro" }
            .map { it.jsonObject["macro_serial_number"]!!.jsonPrimitive.long })
        assertEquals(target.request, variant.variant.request.request)
        assertEquals(proposal.variants.single().settings.cph, variant.cph)
        assertEquals(listOf("normal", "expired-session"), variant.variant.requiredBranches)
        assertEquals(logout.request, variant.variant.branchSetup.getValue("expired-session").single().request)
        assertEquals(1, variant.project["project_options"]!!.jsonObject["resource_pools"]!!.jsonObject[
            "default_resource_pool"]!!.jsonObject["concurrent_request_limit"]!!.jsonPrimitive.int)
    }
    @Test fun `stored planning keeps conditional recovery and selected response last without per-request logout`() {
        val proposal = proposal(true)
        val compiled = JobCompiler().compile(proposal, baseline)
        val actions = compiledActions(compiled.variants.last())
        assertEquals(action(), actions.first())
        assertEquals("run_post_request_macro", actions.last().jsonObject["type"]!!.jsonPrimitive.content)
        assertEquals("final_response", actions.last().jsonObject["pass_back"]!!.jsonPrimitive.content)
        assertEquals(storedSerial, actions.last().jsonObject["macro_serial_number"]!!.jsonPrimitive.long)
        assertEquals(proposal.variants.last().settings.cph, compiled.variants.last().cph)
        assertEquals(proposal.session, compiled.proposal.session)
        assertEquals(proposal.cleanupPolicy, compiled.proposal.cleanupPolicy)
    }
    @Test fun `missing recovery macro fails structurally before any execution`() {
        val proposal = proposal()
        val v = proposal.variants.single()
        val missing = v.settings.macros.filter { it.jsonObject["serial_number"]!!.jsonPrimitive.long != recoverySerial }
        val error = assertThrows(JobRejected::class.java) {
            JobCompiler().compile(proposal.copy(variants = listOf(v.copy(settings = v.settings.copy(macros = JsonArray(missing))))), baseline)
        }
        assertEquals("MISSING_MACRO_REFERENCE", error.code)
    }
    @Test fun `mutating authentication probe is rejected rather than sent to establish readiness`() {
        val proposal = proposal()
        val invalid = material(probe.id, "/protected", "POST", "change=true")
        val error = assertThrows(JobRejected::class.java) {
            JobCompiler().compile(proposal.copy(materials = proposal.materials.map { if (it.id == probe.id) invalid else it }), baseline)
        }
        assertEquals("READ_ONLY_SESSION_PROBE_REQUIRED", error.code)
    }
}
