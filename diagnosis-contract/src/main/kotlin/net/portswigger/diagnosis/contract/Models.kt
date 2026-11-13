package net.portswigger.diagnosis.contract

import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

val jobJson = Json { encodeDefaults = true; ignoreUnknownKeys = false }
fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
fun digest(text: String): String = digest(text.toByteArray(Charsets.UTF_8))
/** Object keys are canonical, but arrays (and the explicit CPH tab order) retain their semantics. */
fun canonical(value: JsonElement): String = when (value) {
    is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (k,v) -> "${JsonPrimitive(k)}:${canonical(v)}" }
    is JsonArray -> value.joinToString(",", "[", "]") { canonical(it) }
    else -> value.toString()
}
inline fun <reified T> fingerprint(value: T): String = digest(canonical(jobJson.encodeToJsonElement(value)))
class JobRejected(val code: String) : IllegalArgumentException(code)
fun requireJob(condition: Boolean, code: String) { if (!condition) throw JobRejected(code) }

@Serializable data class Endpoint(val scheme: String, val host: String, val port: Int, val path: String) {
    fun url(): String = "$scheme://$host:$port$path"
    fun validate() {
        requireJob(scheme in setOf("http", "https") && port in 1..65535 && host.isNotBlank() &&
            !host.contains(Regex("[\\s/@?#]")) && path.startsWith('/') && !path.contains(Regex("[\\r\\n#]")), "INVALID_ENDPOINT")
        var decoded=path.substringBefore('?')
        requireJob(!Regex("%(?![0-9a-fA-F]{2})").containsMatchIn(decoded),"AMBIGUOUS_PATH")
        repeat(4) {
            requireJob(!decoded.contains('\\') && decoded.split('/').none { it=="." || it==".." },"AMBIGUOUS_PATH")
            if(!Regex("%[0-9a-fA-F]{2}").containsMatchIn(decoded)) return@repeat
            val next=try { URLDecoder.decode(decoded.replace("+","%2B"),StandardCharsets.UTF_8) } catch(e:Exception) { throw JobRejected("AMBIGUOUS_PATH") }
            if(next==decoded) return@repeat
            decoded=next
        }
        requireJob(!decoded.contains('\\') && decoded.split('/').none { it=="." || it==".." } &&
            !Regex("(?i)%(25|2e|2f|5c)").containsMatchIn(decoded),"AMBIGUOUS_PATH")
    }
}
fun endpoint(url: String): Endpoint {
    // Braces are valid literal placeholders in Burp's prepared URLs, but not in java.net.URI.
    val u = URI(url.replace("{", "%7B").replace("}", "%7D"))
    requireJob(u.userInfo == null && u.fragment == null, "INVALID_URL_AUTHORITY")
    return Endpoint(u.scheme ?: "", u.host ?: "", if (u.port > 0) u.port else if (u.scheme == "https") 443 else 80,
        (u.rawPath.ifEmpty { "/" } + (u.rawQuery?.let { "?$it" } ?: "")).replace("%7B", "{").replace("%7D", "}")).also { it.validate() }
}
@Serializable data class TargetPermit(val endpoint: Endpoint, val pathPrefix: Boolean = false) {
    fun allows(e: Endpoint): Boolean {
        val p = endpoint.path.substringBefore('?'); val actual = e.path.substringBefore('?')
        return endpoint.scheme == e.scheme && endpoint.host.equals(e.host, true) && endpoint.port == e.port &&
            (actual == p || pathPrefix && actual.startsWith(p.trimEnd('/') + "/"))
    }
}
@Serializable data class HttpMaterial(val id: String, val endpoint: Endpoint, val request: String, val response: String,
    val requestSha256: String, val responseSha256: String)
@Serializable data class RequestPlan(val endpoint: Endpoint, val request: String, val sourceId: String,
    val sourceRequestSha256: String, val startOptions: JsonObject = JsonObject(emptyMap()))
@Serializable data class SessionPlan(val authenticationRequired: Boolean, val validationDecision: String,
    val decisionReason: String, val accountRef: String, val secretGenerations: Map<String, String> = emptyMap(),
    val validationSourceId:String? = null)
@Serializable data class DynamicBinding(val id: String, val source: String, val destination: String,
    val extraction: String, val insertion: String, val timing: String, val failurePolicy: String,
    val dependsOn: List<String> = emptyList())
@Serializable data class LiteralSubstitution(val before:String,val after:String)
@Serializable data class MacroPreparation(val macroSerialNumber:Long,val itemIndex:Int,val sourceId:String,
    val sourceRequestSha256:String,val substitutions:List<LiteralSubstitution> = emptyList(),val cphTrigger:String? = null)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class SettingsPlan(val macros: JsonArray = JsonArray(emptyList()), val rules: JsonArray = JsonArray(emptyList()),
    val cph: JsonObject = JsonObject(emptyMap()), val cphOrder: List<String> = emptyList(),
    val targetScope: JsonObject? = null,val macroPreparations:List<MacroPreparation> = emptyList(),
    // Omit the default so persisted pre-existing proposals retain their canonical digest.
    @EncodeDefault(EncodeDefault.Mode.NEVER) val serialScannerRequests:Boolean = false)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class ScanVariant(val id: String, val kind: String, val verificationSourceId: String? = null,
    val request: RequestPlan, val settings: SettingsPlan, val requiredBranches: List<String> = listOf("normal"),
    val branchSetup: Map<String,List<RequestPlan>> = emptyMap(),
    // Keep legacy persisted proposals/digests unchanged when these safeguards are unused.
    @EncodeDefault(EncodeDefault.Mode.NEVER) val inputExclusions:List<InputExclusion> = emptyList(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val preparationOnce:List<RequestPlan> = emptyList())
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class JobProposal(val schemaVersion: Int = 1, val jobId: String, val revision: Int,
    val objective: String, val targetPolicy: List<TargetPermit>, val materials: List<HttpMaterial>,
    val session: SessionPlan, val dynamicBindings: List<DynamicBinding> = emptyList(), val variants: List<ScanVariant>,
    val storedVerificationSourceIds: List<String> = emptyList(), val requiredCapabilities: Set<String>,
    val cleanupPolicy: String, val validationMaxAgeSeconds: Long = 3600,
    val limitations: List<String> = emptyList(), val inputDigests: Map<String,String> = emptyMap(),
    // Explicitly reviewed duration; omission preserves existing plan digests and the one-hour default.
    @EncodeDefault(EncodeDefault.Mode.NEVER) val executionApprovalMaxAgeSeconds:Long = 3600,
    // Independent requested scope: an exclusion explanation cannot remove requested inputs.
    @EncodeDefault(EncodeDefault.Mode.NEVER) val requestedInputParameters:List<InputParameter> = emptyList())
@Serializable data class BurpSnapshot(val instanceId: String, val project: JsonObject, val cph: JsonObject,
    val cphOrder: List<String>, val capabilities: Set<String>, val adapterVersion: String = "jobs-v1")
@Serializable data class CompiledVariant(val variant: ScanVariant, val project: JsonObject, val cph: JsonObject,
    val cphOrder: List<String>, val settingsDigest: String)
@Serializable data class CompiledPlan(val proposal: JobProposal, val proposalDigest: String, val planDigest: String,
    val baseline: BurpSnapshot, val variants: List<CompiledVariant>, val expandedEndpoints: List<Endpoint>)
@Serializable enum class ApprovalStage { PREPARATION, EXECUTION, RECOVERY }
@Serializable data class ApprovalRecord(val id: String, val executionId: String, val planDigest: String,
    val stage: ApprovalStage, val approvedAt: Long, val expiresAt: Long, val approver: String,
    val reportDigest: String? = null, val revokedAt: Long? = null)
@Serializable data class ProbeEvidence(val variantId: String, val branch: String, val index: Int,
    val settingsDigest: String, val response: String, val logger: JsonObject, val observedAt: Long)
@Serializable data class PreparationEvidence(val variantId:String,val index:Int,val settingsDigest:String,
    val response:String,val logger:JsonObject,val observedAt:Long)
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class ValidationReport(val planDigest: String, val probes: List<ProbeEvidence>, val completedAt: Long,
    val restored: Boolean, val residualCphTabs: List<String>,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val preparationOnce:List<PreparationEvidence> = emptyList())
@Serializable data class ExecutionRecord(val executionId: String, val planDigest: String, val epoch: String,
    val fence: Long, val state: String = "DRAFT", val variantIndex: Int = 0,
    val auditId: String? = null, val payloadRunId: String? = null,
    val evidenceState: String = "NOT_COLLECTED", val cleanupState: String = "NOT_VERIFIED",
    val diagnosisState: String = "NOT_REVIEWED", val warnings: List<String> = emptyList())
@Serializable data class WorkerRequest(val action: String, val executionId: String, val body: JsonObject = JsonObject(emptyMap()))
@Serializable data class WorkerReply(val success: Boolean, val body: JsonElement = JsonNull, val errorCode: String? = null)

/** Definitions only. Never ignore an unknown field or every response in a blanket fashion. */
fun cphDefinitions(cph: JsonObject): JsonObject = JsonObject(cph.mapValues { (_, value) ->
    val tab = value.jsonObject
    // Production EXTRACT_SINGLE calls issue_request on every extraction. That response viewer is runtime state.
    // In other modes preserve single_response as part of the approved definition.
    if (tab["dynamic_checkbox"]?.jsonPrimitive?.booleanOrNull == true &&
        tab["extract_choice_index"]?.jsonPrimitive?.intOrNull == 0) JsonObject(tab - "single_response") else tab
})
/** Only observed native default omissions are equivalent; raw proposal JSON is unchanged. */
fun projectDefinitions(project:JsonObject):JsonObject = macroDefaults(emptySpecifiedParams(project))
private fun macroDefaults(project:JsonObject):JsonObject {
    val wrapped=project["project_options"] is JsonObject
    val root=if(wrapped) project.getValue("project_options").jsonObject else project
    val sessions=root["sessions"] as? JsonObject ?: return project
    val container=sessions["macros"] as? JsonObject ?: return project
    val macros=container["macros"] as? JsonArray ?: return project
    val normalized=JsonArray(macros.map { value ->
        val macro=value as? JsonObject ?: return@map value
        val items=macro["items"] as? JsonArray ?: return@map value
        JsonObject(macro+("items" to JsonArray(items.map item@ { item ->
            val fields=item as? JsonObject ?: return@item item
            val parameters=fields["request_parameters"] as? JsonArray ?: return@item item
            JsonObject(fields+("request_parameters" to JsonArray(parameters.map { parameter ->
                val p=parameter as? JsonObject
                if(p?.get("parameter_handling")==JsonPrimitive("derive_from_prior_response") && p["prior_response_index"]==JsonPrimitive(0))
                    JsonObject(p-"prior_response_index") else parameter
            })))
        })))
    })
    val changed=JsonObject(root+("sessions" to JsonObject(sessions+("macros" to JsonObject(container+("macros" to normalized))))))
    return if(wrapped) JsonObject(project+("project_options" to changed)) else changed
}
/** Burp 2026.10 omits this empty list on export. No other action field is ignored. */
private fun emptySpecifiedParams(project:JsonObject):JsonObject {
    val wrapped=project["project_options"] is JsonObject
    val root=if(wrapped) project.getValue("project_options").jsonObject else project
    val sessions=root["sessions"] as? JsonObject ?: return project
    val handling=sessions["session_handling_rules"] as? JsonObject ?: return project
    val rules=handling["rules"] as? JsonArray ?: return project
    val normalized=JsonArray(rules.map { element ->
        val rule=element as? JsonObject ?: return@map element
        val actions=rule["actions"] as? JsonArray ?: return@map element
        JsonObject(rule+("actions" to JsonArray(actions.map { value ->
            val action=value as? JsonObject
            fun normalizeMacro(fields:JsonObject):JsonObject =
                if(fields["match_params"]==JsonPrimitive("specified") && fields["specified_params"]==JsonArray(emptyList()))
                    JsonObject(fields-"specified_params") else fields
            when {
                action?.get("type")==JsonPrimitive("run_macro") -> normalizeMacro(action)
                action?.get("type")==JsonPrimitive("validate_session") && action["action"]==JsonPrimitive("run_macro") && action["run_macro_action"] is JsonObject ->
                    JsonObject(action+("run_macro_action" to normalizeMacro(action.getValue("run_macro_action").jsonObject)))
                else -> value
            }
        })))
    })
    val newHandling=JsonObject(handling+("rules" to normalized))
    val newSessions=JsonObject(sessions+("session_handling_rules" to newHandling))
    val newRoot=JsonObject(root+("sessions" to newSessions))
    return if(wrapped) JsonObject(project+("project_options" to newRoot)) else newRoot
}
fun settingsDigest(project: JsonObject, cph: JsonObject, order: List<String>): String = fingerprint(buildJsonObject {
    put("project", projectDefinitions(project)); put("cph", cphDefinitions(cph)); put("cphOrder", jobJson.encodeToJsonElement(order))
})
