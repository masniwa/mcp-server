package net.portswigger.mcp.jobs

import burp.api.montoya.MontoyaApi
import io.mockk.*
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.mcp.execution.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.nio.file.*

class MontoyaAdapterTest {
    @Test fun normalStreamingCollectionReadsOneIssueAtATimeAndSavesBeforeNextRead() {
        var saved=0
        dispatch.register("get_active_scan_status") { listOf(TextContent("""{"audit":{"auditId":"audit","completed":true}}""")) }
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","retainedEntries":0,"captureErrors":0,"droppedEntries":0}""")) }
        dispatch.register("get_scanner_issues") { args ->
            assertEquals(JsonPrimitive(1),args["count"])
            val offset=args.getValue("offset").jsonPrimitive.int
            assertEquals(offset,saved)
            listOf(TextContent(if(offset==3) "Reached end of items" else "issue-$offset"))
        }
        val result=port().collectTo("audit",null) { source,page ->
            assertEquals("siteMapIssues",source);assertEquals(JsonPrimitive("issue-$saved"),page)
            saved++;buildJsonObject { put("key","page-$saved") }
        }
        assertEquals(3,saved);assertEquals(JsonPrimitive(true),result["complete"])
        assertEquals(JsonPrimitive("STORE_REFERENCES_V1"),result["evidencePageFormat"])
    }
    @Test fun auditHistoricalCaptureErrorShouldAllowNewStartWindow() {
        net.portswigger.mcp.tools.LoggerHttpHistory().use { history ->
            historyCounter(history,"errors",1L)
            assertEquals(JsonPrimitive("NO_WINDOW_LOSS_OBSERVED"),history.recoveryObservation(history.status())["captureHealth"])
            var starts=0
            dispatch.register("start_active_scan") { starts++;listOf(TextContent("""{"status":"started","auditId":"new-audit"}""")) }
            val port=port(logger=history)
            val result=assertDoesNotThrow<JsonObject> { port.start(captureVariant()) }
            assertEquals(JsonPrimitive("new-audit"),result["auditId"]);assertEquals(1,starts)
            wireProbe(history)
            dispatch.register("get_active_scan_status") { listOf(TextContent("""{"success":true,"audit":{"auditId":"new-audit","completed":true}}""")) }
            dispatch.register("get_scanner_issues") { listOf(TextContent("Reached end of items")) }
            assertEquals(JsonPrimitive(true),port.collect("new-audit",null)["complete"])
            historyCounter(history,"errors",2L)
            assertEquals(JsonPrimitive(false),port.collect("new-audit",null)["complete"])
        }
    }


    private fun historyCounter(history:net.portswigger.mcp.tools.LoggerHttpHistory,name:String,value:Long) {
        val field=history.javaClass.getDeclaredField(name);field.isAccessible=true;field.setLong(history,value)
    }
    private fun captureVariant()=ScanVariant("r","REFLECTION",request=RequestPlan(Endpoint("http","fixture.invalid",80,"/"),"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","observed","digest"),settings=SettingsPlan())
    private fun wireProbe(history:net.portswigger.mcp.tools.LoggerHttpHistory,onSend:()->Unit = {}) {
        val service=net.portswigger.mcp.schema.HttpService("fixture.invalid",80,false)
        dispatch.register("get_logger_history_status") { listOf(TextContent(Json.encodeToString(net.portswigger.mcp.tools.LoggerHistoryStatus.serializer(),history.status()))) }
        dispatch.registerWorkerHttp1 { args ->
            onSend()
            val request=args["content"]!!.jsonPrimitive.content
            history.recordRequest(501,"EXTENSIONS",service,"http://fixture.invalid/",request,null)
            history.recordResponse(501,"EXTENSIONS",service,"http://fixture.invalid/",request,"HTTP/1.1 200 OK\r\n\r\ncurrent",null)
            "HTTP/1.1 200 OK\r\n\r\ncurrent"
        }
    }
    @Test fun auditHistoricalCaptureErrorShouldAllowFreshHealthyProbeWindow() {
        net.portswigger.mcp.tools.LoggerHttpHistory().use { history ->
            historyCounter(history,"errors",1L)
            val checkpoint=history.status()
            assertEquals(JsonPrimitive("NO_WINDOW_LOSS_OBSERVED"),history.recoveryObservation(checkpoint)["captureHealth"])
            var sends=0;wireProbe(history) { sends++ }
            val port=port(logger=history)
            assertTrue(assertDoesNotThrow<Pair<String,JsonObject>> { port.probe(captureVariant(),"normal") }.first.contains("current"))
            assertEquals(1,sends);assertEquals(1L,history.status().captureErrors)
        }
    }
    @Test fun auditCaptureErrorDuringFreshProbeMustStillRefuse() {
        net.portswigger.mcp.tools.LoggerHttpHistory().use { history ->
            wireProbe(history) { historyCounter(history,"errors",1L) }
            val port=port(logger=history)
            assertEquals("LOGGER_INCOMPLETE",assertThrows(JobRejected::class.java) { port.probe(captureVariant(),"normal") }.code)
        }
    }
    @Test fun auditHistoricalMissingResponseDoesNotBlockFreshHealthyProbeWindow() {
        net.portswigger.mcp.tools.LoggerHttpHistory().use { history ->
            val service=net.portswigger.mcp.schema.HttpService("fixture.invalid",80,false)
            history.recordRequest(1,"SCANNER",service,"http://fixture.invalid/","old-unanswered",null)
            val checkpoint=history.status()
            assertEquals(JsonPrimitive("NO_WINDOW_LOSS_OBSERVED"),history.recoveryObservation(checkpoint)["captureHealth"])
            wireProbe(history);val port=port(logger=history)
            val result=assertDoesNotThrow<Pair<String,JsonObject>> { port.probe(captureVariant(),"normal") }
            assertTrue(result.first.contains("current"));assertFalse(result.second.getValue("pages").toString().contains("old-unanswered"))
        }
    }


    private val api=mockk<MontoyaApi>(relaxed=true)
    private val cph=mockk<CphClient>(relaxed=true)
    private val dispatch=ToolDispatch(true)
    private val project=jobJson.parseToJsonElement("""{"project_options":{"sessions":{}},"target":{"scope":{"include":[]}}}""").jsonObject
    private fun port(allow:Boolean=true,logger:net.portswigger.mcp.tools.LoggerHttpHistory?=null,generations:()->Map<String,String> = {emptyMap()}):MontoyaJobPort {
        every { api.burpSuite().exportProjectOptionsAsJson() } returns project.toString()
        every { cph.export() } returns JsonObject(emptyMap())
        val temp=Path.of("..","temp").toAbsolutePath().normalize();Files.createDirectories(temp)
        return MontoyaJobPort(api,dispatch,cph,"instance",emptySet(),Files.createTempDirectory(temp,"montoya-adapter-"),listOf(temp),allowConfigurationEditing={allow},secretGenerations=generations,loggerHistory=logger)
    }
    @Test fun `adapter applies native JSON and complete CPH order without reimplementing extraction`() {
        val port=port();val e=Endpoint("http","fixture.invalid",80,"/")
        val v=ScanVariant("r","REFLECTION",request=RequestPlan(e,"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","obs","digest"),settings=SettingsPlan())
        val config=buildJsonObject { putJsonObject("job:test:source") { put("enabled",true) };putJsonObject("job:test:destination") { put("cached_selection","job:test:source") } }
        val patch=buildJsonObject { putJsonObject("fixture_settings") { put("owned",true) } }
        val target=JsonObject(project+patch)
        var observed=project
        val suite=api.burpSuite()
        every { suite.exportProjectOptionsAsJson() } answers { observed.toString() }
        every { suite.importProjectOptionsFromJson(patch.toString()) } answers { observed=target;Unit }
        val compiled=CompiledVariant(v,target,config,config.keys.toList(),settingsDigest(target,config,config.keys.toList()))
        port.apply(compiled)
        verify(exactly=1) { suite.importProjectOptionsFromJson(patch.toString()) }
        assertEquals(target,observed)
        verify(exactly=1) { cph.apply(config,listOf("job:test:source","job:test:destination"),JsonObject(emptyMap()),match { it.startsWith("adapter:") }) }
    }
    @Test fun `actual HTTP probe arguments use existing MCP sender and preserve bytes`() {
        val port=port();val raw="POST /api HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\nname=__attack__"
        var sent:JsonObject?=null
        dispatch.registerWorkerHttp1 { sent=it;"HTTP/1.1 200 OK\r\n\r\nresult" }
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","retainedEntries":0,"latestId":0,"droppedEntries":0,"captureErrors":0}""")) }
        val v=ScanVariant("r","REFLECTION",request=RequestPlan(Endpoint("http","fixture.invalid",8080,"/api"),raw,"obs","digest"),settings=SettingsPlan())
        assertTrue(port.probe(v,"normal").first.contains("result"))
        assertEquals(raw,sent!!["content"]!!.jsonPrimitive.content)
        assertEquals("fixture.invalid",sent!!["targetHostname"]!!.jsonPrimitive.content)
        assertFalse(sent!!["usesHttps"]!!.jsonPrimitive.boolean)
    }
    @Test fun `capture loss or data permission denial does not become successful validation`() {
        val port=port()
        dispatch.registerWorkerHttp1 { "HTTP/1.1 200 OK\r\n\r\nresult" }
        var reads=0
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","retainedEntries":0,"latestId":0,"droppedEntries":${if(reads++==0) 0 else 1},"captureErrors":0}""")) }
        val v=ScanVariant("r","REFLECTION",request=RequestPlan(Endpoint("http","fixture.invalid",80,"/"),"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","obs","digest"),settings=SettingsPlan())
        assertEquals("LOGGER_INCOMPLETE",assertThrows(JobRejected::class.java) { port.probe(v,"normal") }.code)
    }
    @Test fun `probe evidence contains only its own window instead of duplicating prior history`() {
        net.portswigger.mcp.tools.LoggerHttpHistory().use { history ->
            val service=net.portswigger.mcp.schema.HttpService("fixture.invalid",80,false)
            repeat(500) { history.recordRequest(it,"SCANNER",service,"http://fixture.invalid/","old-$it",null);history.recordResponse(it,"SCANNER",service,"http://fixture.invalid/","old-$it","old-response",null) }
            val port=port(logger=history)
            dispatch.register("get_logger_history_status") { listOf(TextContent(Json.encodeToString(net.portswigger.mcp.tools.LoggerHistoryStatus.serializer(),history.status()))) }
            dispatch.registerWorkerHttp1 { args ->
                val request=args["content"]!!.jsonPrimitive.content
                history.recordRequest(501,"EXTENSIONS",service,"http://fixture.invalid/",request,null)
                history.recordResponse(501,"EXTENSIONS",service,"http://fixture.invalid/",request,"HTTP/1.1 200 OK\r\n\r\ncurrent",null)
                "HTTP/1.1 200 OK\r\n\r\ncurrent"
            }
            val variant=ScanVariant("r","REFLECTION",request=RequestPlan(Endpoint("http","fixture.invalid",80,"/"),"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","observed","digest"),settings=SettingsPlan())
            val logger=port.probe(variant,"normal").second
            val pages=logger["pages"]!!.jsonArray
            assertEquals(1,pages.size)
            val entry=Json.parseToJsonElement(pages.single().jsonPrimitive.content).jsonObject
            assertEquals(501,entry["id"]!!.jsonPrimitive.int)
            assertFalse(pages.toString().contains("old-response"))
        }
    }
    @Test fun `missing capture cursor refuses a probe before target transport`() {
        val port=port();var sent=false
        dispatch.registerWorkerHttp1 { sent=true;"HTTP/1.1 200 OK\r\n\r\n" }
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","droppedEntries":0,"captureErrors":0}""")) }
        val variant=ScanVariant("r","REFLECTION",request=RequestPlan(Endpoint("http","fixture.invalid",80,"/"),"GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","observed","digest"),settings=SettingsPlan())
        assertEquals("LOGGER_METADATA_MISSING",assertThrows(JobRejected::class.java) { port.probe(variant,"normal") }.code)
        assertFalse(sent)
    }
    @Test fun `payload collector reads every page and preserves site-map issue attribution`() {
        val port=port();val offsets=mutableListOf<Int>()
        dispatch.register("get_payload_scan_results") { args ->
            val offset=args["offset"]!!.jsonPrimitive.int;offsets.add(offset)
            listOf(TextContent(buildJsonObject {
                put("completed",true);put("payloadCallbackFinished",true);put("totalCandidates",205)
                putJsonArray("items") { repeat(minOf(100,205-offset)) { add(JsonPrimitive(offset+it)) } }
            }.toString()))
        }
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","retainedEntries":0,"latestId":0,"droppedEntries":0,"captureErrors":0}""")) }
        dispatch.register("get_scanner_issues") { listOf(TextContent("Reached end of items")) }
        dispatch.register("get_active_scan_status") { listOf(TextContent("""{"success":true,"audit":{"auditId":"audit","completed":true,"auditIssueCount":null}}""")) }
        val result=port.collect("audit","payload")
        assertEquals(listOf(0,100,200),offsets)
        assertEquals("SITE_MAP_NOT_AUDIT_SPECIFIC",result["issueAttribution"]!!.jsonPrimitive.content)
        assertFalse(result["diagnosisCompleted"]!!.jsonPrimitive.boolean)
    }
    @Test fun `payload inputs are frozen preflighted and protected against later file changes`() {
        val port=port()
        val temp=Path.of("..","temp").toAbsolutePath().normalize()
        val workbook=Files.createTempFile(temp,"mock-workbook-",".xlsx");Files.writeString(workbook,"synthetic workbook bytes used only by the mock planner")
        var plans=0
        dispatch.register("plan_payload_scan") { plans++;listOf(TextContent("""{"wirePlanReady":true,"totalCandidates":1,"items":[{"payloadId":"mock"}]}""")) }
        val e=Endpoint("http","fixture.invalid",80,"/");val raw="GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n"
        val v=ScanVariant("r","REFLECTION",request=RequestPlan(e,raw,"obs",digest(raw),buildJsonObject { putJsonObject("payloadProfile") { put("workbookPath",workbook.toString());put("tier","light") } }),settings=SettingsPlan())
        val job=JobProposal(jobId="inputs",revision=1,objective="mock only",targetPolicy=listOf(TargetPermit(e)),materials=emptyList(),
            session=SessionPlan(false,"OMIT","No authentication","fixture"),variants=listOf(v),requiredCapabilities=emptySet(),cleanupPolicy="none")
        val reviewed=job.copy(inputDigests=mapOf(workbook.toString() to digest(Files.readAllBytes(workbook))))
        val reviewedFrozen=port.freezeInputs(reviewed)
        assertEquals(reviewed.inputDigests.values.single(),reviewedFrozen.inputDigests.values.single())
        val beforeChange=Files.readAllBytes(workbook)
        Files.writeString(workbook,"changed after original verification but before freeze")
        val beforePlans=plans
        assertEquals("INPUT_CHANGED_DURING_FREEZE",assertThrows(JobRejected::class.java) { port.freezeInputs(reviewed) }.code)
        assertEquals(beforePlans,plans)
        Files.write(workbook,beforeChange);plans=0
        val frozen=port.freezeInputs(job)
        assertEquals(1,plans);assertEquals(1,frozen.inputDigests.size)
        Files.writeString(workbook,"the original is changed after snapshotting")
        port.verifyInputs(frozen)
        Files.writeString(Path.of(frozen.inputDigests.keys.single()),"tampered snapshot")
        assertEquals("APPROVED_INPUT_CHANGED",assertThrows(JobRejected::class.java) { port.verifyInputs(frozen) }.code)
    }
    @Test fun `operator secret generation changes invalidate approved account references`() {
        val suite=api.burpSuite()
        var generation="v1"
        val port=port { mapOf("local/tester" to generation) }
        val example=jobJson.decodeFromString<JobProposal>(Files.readString(Path.of("diagnosis-runner","examples","mock-job.json")))
        val proposal=example.copy(session=example.session.copy(secretGenerations=mapOf("local/tester" to "v1")))
        port.verifyInputs(proposal);generation="v2"
        assertEquals("SECRET_GENERATION_CHANGED_OR_UNAVAILABLE",assertThrows(JobRejected::class.java) { port.verifyInputs(proposal) }.code)
        verify(exactly=0) { suite.importProjectOptionsFromJson(any()) }
    }
    @Test fun `worker approval does not bypass the existing configuration edit setting`() {
        val suite=api.burpSuite();val port=port(allow=false)
        val baseline=BurpSnapshot("instance",project,JsonObject(emptyMap()),emptyList(),emptySet())
        assertEquals("CONFIG_EDITING_DISABLED",assertThrows(JobRejected::class.java) { port.restore(baseline,emptySet()) }.code)
        verify(exactly=0) { suite.importProjectOptionsFromJson(any()) }
    }
    @Test fun `native completion alone does not establish payload callback quiescence`() {
        val port=port()
        dispatch.register("get_active_scan_status") { listOf(TextContent("""{"success":true,"audit":{"auditId":"audit","completed":true}}""")) }
        dispatch.register("get_payload_scan_results") { listOf(TextContent("""{"completed":false,"payloadCallbackFinished":false,"totalCandidates":1,"items":[{}]}""")) }
        dispatch.register("get_logger_history_status") { listOf(TextContent("""{"captureId":"capture","retainedEntries":0,"latestId":0,"droppedEntries":0,"captureErrors":0}""")) }
        dispatch.register("get_scanner_issues") { listOf(TextContent("Reached end of items")) }
        val result=port.collect("audit","payload")
        assertFalse(result["quiescent"]!!.jsonPrimitive.boolean);assertFalse(result["complete"]!!.jsonPrimitive.boolean)
    }
    @Test fun `worker unwraps the native single audit status envelope`() {
        val port=port()
        dispatch.register("get_active_scan_status") { args ->
            assertEquals("audit",args["auditId"]!!.jsonPrimitive.content)
            listOf(TextContent("""{"success":true,"audit":{"auditId":"audit","completed":true,"auditStatusMessage":"finished","auditRequestCount":259,"auditErrorCount":0,"auditIssueCount":null}}"""))
        }
        val status=port.poll("audit")
        assertTrue(status["completed"]!!.jsonPrimitive.boolean)
        assertEquals(259,status["auditRequestCount"]!!.jsonPrimitive.int)
        assertEquals(JsonNull,status["auditIssueCount"])
    }
    @Test fun `unknown native completion and submission errors remain unknown inside the envelope`() {
        val port=port()
        dispatch.register("get_active_scan_status") { listOf(TextContent("""{"success":true,"audit":{"auditId":"audit","completed":null,"nativeCompleted":true,"submissionError":"uncertain"}}""")) }
        val status=port.poll("audit")
        assertEquals(JsonNull,status["completed"])
        assertEquals("uncertain",status["submissionError"]!!.jsonPrimitive.content)
    }
    @Test fun `missing or mismatched native audit is rejected rather than guessed complete`() {
        val port=port()
        for(raw in listOf("""{"success":true,"audits":[]}""","""{"success":true,"audit":{"auditId":"another","completed":true}}""")) {
            dispatch.register("get_active_scan_status") { listOf(TextContent(raw)) }
            assertThrows(JobRejected::class.java) { port.poll("audit") }
        }
    }
    @Test fun `CPH client does not follow a redirect to an unapproved API destination`() {
        val redirects=java.util.concurrent.atomic.AtomicInteger()
        val receiver=com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1",0),0)
        val source=com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1",0),0)
        receiver.createContext("/") { exchange -> redirects.incrementAndGet();exchange.sendResponseHeaders(200,-1);exchange.close() }
        source.createContext("/cph/export") { exchange ->
            exchange.responseHeaders.add("Location","http://127.0.0.1:${receiver.address.port}/stolen")
            exchange.sendResponseHeaders(302,-1);exchange.close()
        }
        receiver.start();source.start()
        try {
            assertEquals(302,CphClient().exchange("/cph/export",port=source.address.port).first)
            assertEquals(0,redirects.get())
        } finally { source.stop(0);receiver.stop(0) }
    }
}
