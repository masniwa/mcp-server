package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/** Synthetic observed-material fixture. It tests plan preservation, not native Macro/CPH execution. */
internal object LoginPreparationFixture {
    val caps=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT","DYNAMIC_WORKFLOW_VERIFIED")
    private val root=Endpoint("http","fixture.invalid",8080,"/")
    private val prefix="job:login-preparation:"
    private fun material(id:String,path:String,method:String="GET",body:String=""):HttpMaterial {
        val request="$method $path HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n$body"
        val response="HTTP/1.1 200 OK\r\n\r\n$id"
        return HttpMaterial(id,root.copy(path=path),request,response,digest(request),digest(response))
    }
    val login=material("normal-login","/login","POST","username=tester&password=fixture-secret&csrf=observed-token")
    private val form=material("form","/login")
    val logout=material("logout","/logout")
    val baseline=BurpSnapshot("fixture",buildJsonObject { putJsonObject("project_options") {
        putJsonObject("sessions") {}
        putJsonObject("resource_pools") { putJsonObject("default_resource_pool") {
            put("concurrent_request_limit_enabled",true);put("concurrent_request_limit",10)
        } }
    } },JsonObject(emptyMap()),emptyList(),caps)
    private fun macro(serial:Long,name:String,materials:List<HttpMaterial>)=buildJsonObject {
        put("description",prefix+name);put("serial_number",serial)
        put("items",JsonArray(materials.map { source -> buildJsonObject {
            put("url",source.endpoint.url());put("request",source.request);put("response",source.response)
            put("method",source.request.substringBefore(' '));put("status_code",200)
            put("accept_response_cookies",true);put("use_request_cookies",true)
            put("custom_parameters",JsonArray(emptyList()));put("request_parameters",JsonArray(emptyList()))
        } }))
    }
    fun proposal():JobProposal {
        val source=prefix+"session-source";val destination=prefix+"current-issued-session"
        val cph=buildJsonObject {
            putJsonObject(source) {
                put("enabled",true);put("dynamic_checkbox",false);put("extract_choice_index",0)
                put("single_request",login.request);put("single_response",login.response)
            }
            putJsonObject(destination) {
                put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",2)
                put("cached_selection",source)
                putJsonArray("cached_expression") { add(true);add("sessionid=(?P<sid>[a-z]+)") }
            }
        }
        val pre=buildJsonObject {
            put("type","run_macro");put("enabled",true);put("macro_serial_number",101)
            put("invoke_extension_action",false);put("match_cookies","all_except");put("match_params","specified")
            putJsonArray("specified_params") { add("csrf") }
            put("tolerate_url_mismatch",false);put("update_with_cookies",true);put("update_with_params",true)
        }
        val post=buildJsonObject {
            put("type","run_post_request_macro");put("enabled",true);put("macro_serial_number",102)
            put("pass_back","current_response");put("match_params","all_except");put("update_with_params",true)
        }
        val rule=buildJsonObject {
            put("description",prefix+"login-reflection");put("enabled",true)
            put("actions",JsonArray(listOf(pre,post)));put("exclude_from_scope",JsonArray(emptyList()))
            put("named_params",JsonArray(emptyList()));put("restrict_scope_to_named_params",false)
            putJsonArray("tools_scope") { add("Scanner");add("Extensions") }
            put("url_scope","custom");put("url_scope_advanced_mode",false)
            putJsonArray("include_in_scope") { add(buildJsonObject {
                put("enabled",true);put("include_subdomains",false);put("prefix",login.endpoint.url())
            }) }
        }
        val settings=SettingsPlan(macros=JsonArray(listOf(macro(101,"normal-login-and-pre-logout",listOf(form,login,logout,form)),
            macro(102,"post-logout",listOf(logout)))),rules=JsonArray(listOf(rule)),cph=cph,cphOrder=listOf(source,destination),serialScannerRequests=true)
        val selectors=buildJsonObject { putJsonArray("insertionPointParameters") {
            for(name in listOf("username","password")) add(buildJsonObject { put("name",name);put("type","BODY") })
        } }
        return JobProposal(jobId="login-preparation",revision=1,objective="Prepare the normal four-stage login workflow",
            targetPolicy=listOf(TargetPermit(root,true)),materials=listOf(form,login,logout),
            session=SessionPlan(true,"OMIT","Login itself requires normal prerequisite login and pre/post logout isolation","owned-fixture-account"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(login.endpoint,login.request,login.id,login.requestSha256,selectors),settings=settings)),
            requiredCapabilities=caps,cleanupPolicy="Invalidate only each newly issued diagnostic session",
            requestedInputParameters=listOf(InputParameter("username","BODY"),InputParameter("password","BODY")))
    }
}

class LoginPreparationPlanningTest {
    @Test fun `isolated login compiles with the default normal branch and preserves both logout stages and CPH definitions`() {
        val p=LoginPreparationFixture.proposal();val c=JobCompiler().compile(p,LoginPreparationFixture.baseline).variants.single()
        assertEquals(listOf("normal"),c.variant.requiredBranches);assertTrue(c.variant.branchSetup.isEmpty())
        val macros=c.variant.settings.macros.map { it.jsonObject }
        assertEquals(listOf("GET","POST","GET","GET"),macros[0]["items"]!!.jsonArray.map { it.jsonObject["method"]!!.jsonPrimitive.content })
        assertEquals(LoginPreparationFixture.login.request,macros[0]["items"]!!.jsonArray[1].jsonObject["request"]!!.jsonPrimitive.content)
        assertEquals(LoginPreparationFixture.logout.request,macros[0]["items"]!!.jsonArray[2].jsonObject["request"]!!.jsonPrimitive.content)
        assertEquals(LoginPreparationFixture.logout.request,macros[1]["items"]!!.jsonArray.single().jsonObject["request"]!!.jsonPrimitive.content)
        assertEquals(p.variants.single().settings.cph,c.cph)
        assertEquals("current_response",c.variant.settings.rules.single().jsonObject["actions"]!!.jsonArray.last().jsonObject["pass_back"]!!.jsonPrimitive.content)
    }
    @Test fun `diagnostic credentials and password selector are not replaced by the normal prerequisite credentials`() {
        val p=LoginPreparationFixture.proposal();val v=p.variants.single()
        val attack=v.request.request.replace("username=tester&password=fixture-secret","username=diagnostic-input&password=diagnostic-payload")
        val c=JobCompiler().compile(p.copy(variants=listOf(v.copy(request=v.request.copy(request=attack)))),LoginPreparationFixture.baseline).variants.single()
        assertEquals(attack,c.variant.request.request)
        assertEquals(v.request.startOptions,c.variant.request.startOptions)
        assertEquals(LoginPreparationFixture.login.request,c.variant.settings.macros[0].jsonObject["items"]!!.jsonArray[1].jsonObject["request"]!!.jsonPrimitive.content)
        assertEquals(JsonArray(listOf(JsonPrimitive("csrf"))),c.variant.settings.rules.single().jsonObject["actions"]!!.jsonArray.first().jsonObject["specified_params"])
    }
    @Test fun `a separately specified extra scenario remains explicit and is not generated by the compiler`() {
        val p=LoginPreparationFixture.proposal();val v=p.variants.single()
        val logout=RequestPlan(LoginPreparationFixture.logout.endpoint,LoginPreparationFixture.logout.request,LoginPreparationFixture.logout.id,LoginPreparationFixture.logout.requestSha256)
        val explicit=v.copy(requiredBranches=listOf("normal","owned-session-expired"),branchSetup=mapOf("owned-session-expired" to listOf(logout)))
        val c=JobCompiler().compile(p.copy(variants=listOf(explicit)),LoginPreparationFixture.baseline).variants.single()
        assertEquals(explicit.requiredBranches,c.variant.requiredBranches);assertEquals(explicit.branchSetup,c.variant.branchSetup)
    }
}
