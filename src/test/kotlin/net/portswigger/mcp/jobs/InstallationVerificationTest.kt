package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.diagnosis.runner.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.nio.file.Files
import java.net.URI
import java.net.http.*

/** Real loopback target and production worker, simulated Burp port. This is not a native Burp attestation. */
class InstallationVerificationTest {
    @TempDir lateinit var directory:Path
    private fun ordinaryProposal():JobProposal {
        val endpoint=Endpoint("http","fixture.invalid",8080,"/items")
        val raw="GET /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
        val response="HTTP/1.1 200 OK\r\n\r\nfixture"
        return JobProposal(jobId="ordinary",revision=1,objective="Ordinary gated plan",targetPolicy=listOf(TargetPermit(endpoint)),
            materials=listOf(HttpMaterial("observed",endpoint,raw,response,digest(raw),digest(response))),
            session=SessionPlan(false,"OMIT","Public fixture","fixture"),
            variants=listOf(ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,raw,"observed",digest(raw)),settings=SettingsPlan())),
            requiredCapabilities=setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT"),cleanupPolicy="No persistent records")
    }
    private fun awaitOperation(service:DiagnosticJobService,operation:String,execution:String):JsonObject {
        val deadline=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(8)
        while(System.nanoTime()<deadline) {
            val result=service.call(DiagnosticJob("operation",execution,operationId=operation))
            if(result["state"]!=JsonPrimitive("RUNNING")) return result
            Thread.sleep(10)
        }
        error("Operation did not finish")
    }
    private class Port:BurpExecutionPort {
        var current=BurpSnapshot("fixture",jobJson.parseToJsonElement("""{"project_options":{"sessions":{},"resource_pools":{"default_resource_pool":{"concurrent_request_limit_enabled":true,"concurrent_request_limit":10}}}}""").jsonObject,
            JsonObject(emptyMap()),emptyList(),emptySet())
        var starts=0;var sends=0;var restores=0
        var scannerTool="SCANNER"
        private val rows=mutableListOf<JsonObject>()
        private val http=HttpClient.newHttpClient()
        override fun snapshot()=current
        override fun apply(variant:CompiledVariant) { current=current.copy(project=variant.project,cph=variant.cph,cphOrder=variant.cphOrder) }
        override fun restore(baseline:BurpSnapshot,ownedCphNames:Set<String>) { restores++;current=baseline.copy(capabilities=emptySet()) }
        private fun send(request:RequestPlan,tool:String,dynamic:Boolean=true):String {
            var raw=request.request
            if(dynamic && "{{setup_token}}" in raw && current.cph.isNotEmpty()) {
                val tab=current.cph.values.first().jsonObject
                val source=tab.getValue("single_request").jsonPrimitive.content
                val path=source.substringBefore("\r\n").split(' ')[1]
                val response=send(request.copy(endpoint=request.endpoint.copy(path=path),request=source),"EXTENSIONS",false)
                raw=raw.replace("{{setup_token}}",response.substringAfter("\r\n\r\n"))
            }
            val builder=HttpRequest.newBuilder(URI(request.endpoint.url()))
            raw.substringBefore("\r\n\r\n").split("\r\n").drop(1).filter { it.startsWith("X-") }.forEach {
                builder.header(it.substringBefore(':'),it.substringAfter(':').trim())
            }
            val method=raw.substringBefore(' ')
            val response=http.send(builder.method(method,HttpRequest.BodyPublishers.noBody()).build(),HttpResponse.BodyHandlers.ofString())
            sends++
            val text="HTTP/1.1 ${response.statusCode()} fixture\r\n\r\n${response.body()}"
            rows+=buildJsonObject {
                put("tool",tool);put("request",raw);put("response",text)
                putJsonObject("httpService") { put("host","127.0.0.1");put("port",request.endpoint.port);put("secure",false) }
            }
            return text
        }
        override fun oncePreparation(request:RequestPlan)=send(request,"EXTENSIONS",false) to JsonObject(emptyMap())
        override fun probe(variant:ScanVariant,branch:String)=send(variant.request,"EXTENSIONS") to JsonObject(emptyMap())
        override fun start(variant:ScanVariant):JsonObject {
            starts++;send(variant.request,scannerTool)
            return buildJsonObject { put("status","started");put("auditId","native-fixture-audit") }
        }
        override fun poll(auditId:String)=buildJsonObject { put("auditId",auditId);put("completed",true);put("auditStatusMessage","finished") }
        override fun collect(auditId:String,payloadRunId:String?)=buildJsonObject {
            put("auditId",auditId);put("complete",true);put("quiescent",true)
            putJsonArray("loggerPages") { add(rows.joinToString("\n") { it.toString() }) }
        }
        override fun recoveryReadiness(endpoints:List<Endpoint>)=true
    }
    private fun config(name:String,raw:String,port:Int,response:String,trigger:String)=buildJsonObject {
        putJsonObject(name) {
            put("enabled",true);put("dynamic_checkbox",true);put("extract_choice_index",0)
            put("single_request",raw);put("single_response",response)
            putJsonArray("issuer") { add(false);add("127.0.0.1");add(port) }
            putJsonArray("modify_expression") { add(false);add(trigger) }
            putJsonArray("match_expression") { add(false);add("{{setup_token}}") }
            putJsonArray("single_expression") { add(true);add("(?P<token>[a-f0-9-]{36})") }
            putJsonArray("static_expression") { add(true);add("\\g<token>") }
        }
    }
    private fun approver(install:Boolean=true,job:Boolean=true)=object:HumanApprover {
        override fun reviewInstallation(message:String)=if(install) "human" else null
        override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)=if(job) "human" else null
    }
    private fun profile():Path {
        InstalledRuntime.load(directory)
        return directory.resolve("runtime/settings.json")
    }
    private fun capabilities(path:Path)=jobJson.parseToJsonElement(Files.readString(path)).jsonObject.getValue("verifiedCapabilities").jsonArray.map { it.jsonPrimitive.content }.toSet()
    @Test fun `fresh normal and dynamic installation exercises production lifecycle without enabling the ordinary port`() {
        val profile=profile();val port=Port();val initial=port.snapshot()
        assertTrue(capabilities(profile).isEmpty())
        JobStore(directory.resolve("store")).use { store ->
            val verifier=InstallationVerification(port,store,approver(),profile,::config,{})
            val normal=verifier.run("setup-normal",false)
            assertEquals("native-fixture-audit",normal["auditId"]!!.jsonPrimitive.content)
            assertEquals(setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT"),capabilities(profile))
            assertEquals(initial,port.snapshot());assertEquals(1,port.starts);assertEquals(2,port.restores)
            val dynamic=verifier.run("setup-dynamic",true)
            assertEquals(JsonPrimitive(true),dynamic["registeredForNextLoad"])
            assertEquals(setOf("SCANNER_WORKFLOW","EXCLUSIVE_CONTEXT","DYNAMIC_WORKFLOW_VERIFIED"),capabilities(profile))
            assertEquals(initial,port.snapshot());assertEquals(2,port.starts);assertEquals(4,port.restores)
            assertEquals(JsonNull,store.get("active"))
            assertThrows(JobRejected::class.java) { GuardedWorker(port,store,approver()).register("ordinary",ordinaryProposal()) }
            assertTrue(InstalledRuntime.load(directory).capabilities.containsAll(capabilities(profile)))
            val sends=port.sends
            assertThrows(JobRejected::class.java) { verifier.run("setup-normal",false) }
            assertEquals(sends,port.sends)
        }
    }
    @Test fun `human denial before observation performs no target traffic or registration`() {
        val profile=profile();val port=Port()
        JobStore(directory.resolve("store")).use { store ->
            val verifier=InstallationVerification(port,store,approver(install=false),profile,::config,{})
            assertEquals("HUMAN_DENIED",assertThrows(JobRejected::class.java) { verifier.run("denied",true) }.code)
            assertEquals(0,port.sends);assertTrue(capabilities(profile).isEmpty())
        }
    }
    @Test fun `Extensions traffic cannot stand in for Scanner evidence`() {
        val profile=profile();val port=Port();port.scannerTool="EXTENSIONS"
        JobStore(directory.resolve("store")).use { store ->
            val verifier=InstallationVerification(port,store,approver(),profile,::config,{})
            assertEquals("INSTALLATION_SCANNER_EVIDENCE_REQUIRED",assertThrows(JobRejected::class.java) { verifier.run("wrong-source",false) }.code)
            assertTrue(capabilities(profile).isEmpty());assertEquals(2,port.restores)
        }
    }
    @Test fun `final human denial preserves results and restored settings without registering capabilities`() {
        val profile=profile();val port=Port();var reviews=0
        val human=object:HumanApprover {
            override fun reviewInstallation(message:String)=if(++reviews==1) "human" else null
            override fun review(plan:CompiledPlan,stage:ApprovalStage,report:ValidationReport?)="human"
        }
        JobStore(directory.resolve("store")).use { store ->
            val verifier=InstallationVerification(port,store,human,profile,::config,{})
            assertEquals("HUMAN_DENIED",assertThrows(JobRejected::class.java) { verifier.run("final-denial",true) }.code)
            assertTrue(capabilities(profile).isEmpty());assertEquals(2,port.restores)
            assertEquals("EXECUTION_FINISHED",GuardedWorker(port,store,human).record("final-denial").state)
            assertNotNull(store.get("setup-evidence:final-denial"))
        }
    }
    @Test fun `public job action returns an operation handle and saved audit evidence while normal propose remains gated`() {
        val profile=profile();val port=Port();val human=approver()
        JobStore(directory.resolve("store")).use { store ->
            val verifier=InstallationVerification(port,store,human,profile,::config,{})
            DiagnosticJobService(GuardedWorker(port,store,human),store,false,profile,verifier).use { service ->
                val input=DiagnosticJob("verify_dynamic_workflow","async-setup",operationId="stable-setup")
                val start=service.call(input)
                assertEquals(JsonPrimitive("RUNNING"),start["state"])
                val end=awaitOperation(service,"stable-setup","async-setup")
                assertEquals(JsonPrimitive("SUCCEEDED"),end["state"])
                assertEquals(JsonPrimitive(true),end["lookAheadPlanning"]!!.jsonObject["epochMatches"])
                assertEquals(JsonPrimitive("native-fixture-audit"),end["result"]!!.jsonObject["auditId"])
                assertTrue(service.call(DiagnosticJob("results","async-setup"))["totalRecords"]!!.jsonPrimitive.int>=2)
                assertEquals(end["result"],service.call(input)["result"]);assertEquals(1,port.starts)
                assertThrows(JobRejected::class.java) { service.call(input.copy(proposalJson="{}")) }
                service.call(DiagnosticJob("propose","unregistered-normal",proposalJson=jobJson.encodeToString(ordinaryProposal()),operationId="gated"))
                assertEquals(JsonPrimitive("UNSUPPORTED_CAPABILITY"),awaitOperation(service,"gated","unregistered-normal")["errorCode"])
            }
        }
    }
    @Test fun `busy context is preserved and cannot send installation traffic`() {
        val profile=profile();val port=Port()
        JobStore(directory.resolve("store")).use { store ->
            store.put("active",JsonPrimitive("other"))
            store.put("execution:other",jobJson.encodeToJsonElement(ExecutionRecord("other","digest","old",1)))
            val verifier=InstallationVerification(port,store,approver(),profile,::config,{})
            assertEquals("BURP_CONTEXT_BUSY",assertThrows(JobRejected::class.java) { verifier.run("busy",true) }.code)
            assertEquals(JsonPrimitive("other"),store.get("active"));assertEquals(0,port.sends)
        }
    }
}
