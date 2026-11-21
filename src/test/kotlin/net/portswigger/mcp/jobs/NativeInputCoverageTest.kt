package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import io.mockk.*
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.mcp.execution.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class NativeInputCoverageTest {
    private val body="csrfmiddlewaretoken=token-source&login=reader&password=valid-pass"
    private val raw="POST /login?loggedout=1 HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ${body.length}\r\n\r\n$body"
    private val endpoint=Endpoint("http","fixture.invalid",80,"/login?loggedout=1")
    private val four=listOf(InputParameter("loggedout","URL"),InputParameter("csrfmiddlewaretoken","BODY"),InputParameter("login","BODY"),InputParameter("password","BODY"))
    private val excluded=listOf(InputExclusion("csrfmiddlewaretoken","BODY","Human review requested separate diagnosis of this input"))
    private fun options(parameters:List<InputParameter>)=buildJsonObject { put("insertionPointParameters",jobJson.encodeToJsonElement(parameters)) }
    private fun request(parameters:List<InputParameter>?=four,content:String=raw)=RequestPlan(endpoint,content,"source",digest(content),parameters?.let(::options) ?: JsonObject(emptyMap()))
    private fun action()=jobJson.parseToJsonElement("""{"type":"run_macro","enabled":true,"update_with_params":true,"match_params":"specified","specified_params":["csrfmiddlewaretoken"]}""").jsonObject
    private fun reject(code:String,block:()->Unit) { assertEquals(code,assertThrows(JobRejected::class.java,block).code) }
    private fun nativeParameter(name:String,value:String,type:HttpParameterType,content:String=raw):ParsedHttpParameter {
        val start=content.indexOf(value);assertTrue(start>=0)
        val offsets=mockk<Range> { every { startIndexInclusive() } returns start;every { endIndexExclusive() } returns start+value.length }
        return mockk { every { name() } returns name;every { type() } returns type;every { valueOffsets() } returns offsets }
    }
    private fun nativeParameters(content:String=raw)=listOf(nativeParameter("loggedout","1",HttpParameterType.URL,content),
        nativeParameter("csrfmiddlewaretoken","token-source",HttpParameterType.BODY,content),nativeParameter("login","reader",HttpParameterType.BODY,content),nativeParameter("password","valid-pass",HttpParameterType.BODY,content))
    private fun withNative(parameters:List<ParsedHttpParameter> = nativeParameters(),requestLength:Int=raw.length,block:(HttpRequest)->Unit) {
        mockkStatic(HttpService::class);mockkStatic(HttpRequest::class)
        try {
            val service=mockk<HttpService>();val native=mockk<HttpRequest>(relaxed=true)
            every { HttpService.httpService("fixture.invalid",80,false) } returns service
            every { HttpRequest.httpRequest(service,any<String>()) } returns native
            every { native.parameters() } returns parameters
            every { native.toByteArray().length() } returns requestLength
            block(native)
        } finally { unmockkStatic(HttpRequest::class);unmockkStatic(HttpService::class) }
    }
    @Test fun `native four parameter inventory refuses silent omission and accepts a declared three input scope`() = withNative {
        val selected=four.filterNot { p -> p.name=="csrfmiddlewaretoken" }
        reject("INPUT_EXCLUSION_REQUIRED") { validateNativeInputCoverage(request(selected),emptyList()) }
        validateNativeInputCoverage(request(selected),excluded,listOf(action()))
        reject("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { validateNativeInputCoverage(request(),emptyList(),listOf(action())) }
    }
    @Test fun `automatic selection cannot assume the Macro updated input will not be attacked`() = withNative {
        reject("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { validateNativeInputCoverage(request(null),emptyList(),listOf(action())) }
    }
    @Test fun `Cookie input omitted from an explicit value allowlist must also be reviewed`() {
        val content=raw.replace("Host: fixture.invalid\r\n","Host: fixture.invalid\r\nCookie: sid=observed-session\r\n")
        val parsed=nativeParameters(content)+nativeParameter("sid","observed-session",HttpParameterType.COOKIE,content)
        withNative(parsed,content.length) {
            reject("INPUT_EXCLUSION_REQUIRED") { validateNativeInputCoverage(request(content=content),emptyList()) }
            validateNativeInputCoverage(request(content=content),listOf(InputExclusion("sid","COOKIE","Reviewed authentication context; separate Cookie diagnosis required")))
        }
    }
    @Test fun `independent four input request accepts excluded Cookie context and rejects nonexistent requested inputs natively`() {
        val content=raw.replace("Host: fixture.invalid\r\n","Host: fixture.invalid\r\nCookie: sid=observed-session\r\n")
        val parsed=nativeParameters(content)+nativeParameter("sid","observed-session",HttpParameterType.COOKIE,content)
        withNative(parsed,content.length) {
            val (port,api)=port()
            val observed=HttpMaterial("source",endpoint,content,"HTTP/1.1 200 OK\r\n\r\nnormal",digest(content),digest("HTTP/1.1 200 OK\r\n\r\nnormal"))
            val variant=ScanVariant("reflection","REFLECTION",request=request(content=content),settings=SettingsPlan(),
                inputExclusions=listOf(InputExclusion("sid","COOKIE","Observed authentication context outside the four requested inputs")))
            val caps=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT")
            val proposal=JobProposal(jobId="requested-native",revision=1,objective="Preserve the four requested inputs",targetPolicy=listOf(TargetPermit(endpoint)),
                materials=listOf(observed),session=SessionPlan(false,"OMIT","No authentication in this fixture","fixture"),variants=listOf(variant),
                requiredCapabilities=caps,cleanupPolicy="No owned state",requestedInputParameters=four)
            val baseline=BurpSnapshot("fixture",JsonObject(emptyMap()),JsonObject(emptyMap()),emptyList(),caps)
            val compiled=JobCompiler().compile(proposal,baseline)
            port.validateInputCoverage(compiled)
            assertEquals(four,compiled.proposal.requestedInputParameters)
            assertEquals(listOf("sid"),compiled.variants.single().variant.inputExclusions.map { it.name })
            val absent=four+InputParameter("unobserved","BODY")
            val nonexistent=proposal.copy(requestedInputParameters=absent,variants=listOf(variant.copy(request=variant.request.copy(startOptions=options(absent)))))
            reject("SELECTED_INPUT_NOT_FOUND") { port.validateInputCoverage(JobCompiler().compile(nonexistent,baseline)) }
            verify(exactly=0) { api.http().sendRequest(any<HttpRequest>()) }
            verify(exactly=0) { api.scanner().startAudit(any()) }
        }
    }
    @Test fun `automatic selection without a parameter updating Macro keeps the existing path`() {
        // No Montoya factory is installed: unchanged automatic requests need no new parser dependency.
        validateNativeInputCoverage(request(null),emptyList())
    }
    @Test fun `opaque encoded and unparsed body inventories cannot silently pass a query only scope`() = withNative {
        val query=request(four.take(1))
        reject("INPUT_INVENTORY_UNSUPPORTED_BODY") { validateNativeInputCoverage(query.copy(request=raw.replace("application/x-www-form-urlencoded","application/octet-stream")),emptyList()) }
        reject("INPUT_INVENTORY_UNSUPPORTED_ENCODING") { validateNativeInputCoverage(query.copy(request=raw.replace("Content-Type:","Content-Encoding: gzip\r\nContent-Type:")),emptyList()) }
        reject("INPUT_INVENTORY_UNSUPPORTED_ENCODING") { validateNativeInputCoverage(query.copy(request=raw.replace("Content-Type:","Transfer-Encoding: chunked\r\nContent-Type:")),emptyList()) }
        every { it.parameters() } returns nativeParameters().take(1)
        reject("NATIVE_BODY_INPUT_INVENTORY_UNAVAILABLE") { validateNativeInputCoverage(query,emptyList()) }
    }
    @Test fun `exact native selector offsets are checked before workflow sends`() = withNative { native ->
        val empty=mockk<Range> { every { startIndexInclusive() } returns 100;every { endIndexExclusive() } returns 100 }
        val parameters=native.parameters();every { parameters.last().valueOffsets() } returns empty
        reject("INVALID_NATIVE_INPUT_SELECTION") { validateNativeInputCoverage(request(),emptyList()) }
        verify(atLeast=1) { native.parameters() }
        verify(atLeast=1) { parameters.last().valueOffsets() }
    }
    private fun port():Pair<MontoyaJobPort,MontoyaApi> {
        val api=mockk<MontoyaApi>(relaxed=true)
        val temp=Path.of("..","temp","approval-input-lifecycle-20261113").toAbsolutePath().normalize();Files.createDirectories(temp)
        return MontoyaJobPort(api,ToolDispatch(true),mockk<CphClient>(relaxed=true),"instance",emptySet(),Files.createTempDirectory(temp,"native-input-"),listOf(temp)) to api
    }
    @Test fun `formal freeze rejects omission before configuration HTTP or native audit effects`() = withNative {
        val (port,api)=port()
        val variant=ScanVariant("reflection","REFLECTION",request=request(four.filterNot { p -> p.name=="csrfmiddlewaretoken" }),settings=SettingsPlan())
        val job=JobProposal(jobId="coverage",revision=1,objective="Review all inputs",targetPolicy=listOf(TargetPermit(endpoint)),materials=emptyList(),
            session=SessionPlan(false,"OMIT","No authentication in the mock","fixture"),variants=listOf(variant),requiredCapabilities=emptySet(),cleanupPolicy="None")
        reject("INPUT_EXCLUSION_REQUIRED") { port.freezeInputs(job) }
        verify(exactly=0) { api.http().sendRequest(any<HttpRequest>()) }
        verify(exactly=0) { api.scanner().startAudit(any()) }
        verify(exactly=0) { api.burpSuite().importProjectOptionsFromJson(any()) }
    }
    @Test fun `compiled native guard includes inherited applicable and conditional recovery actions`() = withNative {
        val (port,api)=port()
        val recovery=buildJsonObject { put("type","validate_session");put("action","run_macro");put("perform_action_if_invalid",true);put("run_macro_action",action()) }
        val project=buildJsonObject { putJsonObject("project_options") { putJsonObject("sessions") {
            putJsonObject("session_handling_rules") { putJsonArray("rules") { add(buildJsonObject { put("enabled",true);putJsonArray("actions") { add(recovery) } }) } }
        } } }
        val variant=ScanVariant("reflection","REFLECTION",request=request(null),settings=SettingsPlan())
        val proposal=JobProposal(jobId="coverage",revision=1,objective="Review all inputs",targetPolicy=listOf(TargetPermit(endpoint)),materials=emptyList(),
            session=SessionPlan(false,"OMIT","No authentication in the mock","fixture"),variants=listOf(variant),requiredCapabilities=emptySet(),cleanupPolicy="None")
        val baseline=BurpSnapshot("instance",project,JsonObject(emptyMap()),emptyList(),emptySet())
        val compiled=CompiledVariant(variant,project,JsonObject(emptyMap()),emptyList(),"settings")
        val plan=CompiledPlan(proposal,"proposal","plan",baseline,listOf(compiled),listOf(endpoint))
        reject("MACRO_OVERWRITES_DIAGNOSTIC_INPUT") { port.validateInputCoverage(plan) }
        verify(exactly=0) { api.http().sendRequest(any<HttpRequest>()) }
        verify(exactly=0) { api.scanner().startAudit(any()) }
    }
}
