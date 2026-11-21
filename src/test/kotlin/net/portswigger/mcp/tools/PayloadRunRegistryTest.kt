package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.Audit
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class PayloadRunRegistryTest {
    @TempDir lateinit var root: Path
    @Test fun `main callback completion does not close pending controls and evidence remains separate`() {
        val plan=PayloadWirePlan.create("x=1".toByteArray(),PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p","replace","light","2",listOf("query")))),"light",listOf(PayloadWirePosition("x","query",2,3,0,1)))
        val dir=root.resolve("controls"); val store=PayloadEvidenceStore.create(dir,plan)
        val execution=PayloadExecution(plan)
        val timing=PayloadTimingCollection(listOf(1000L,3000L).map {TimingControlInput(it,"normal".toByteArray(),"true:$it".toByteArray(),"false:$it".toByteArray())})
        val controlStore=PayloadEvidenceStore.createControls(dir.resolve("timing-controls"),timing.snapshot(),plan.requestSha256)
        val run=PayloadRunRegistry.Run("id",plan,execution,store,dir,mockk(),timing,controlStore)
        val audit=mockk<Audit>(); every {audit.statusMessage()} returns "scanning"; run.audit=audit
        execution.execute({true},{PayloadExchange(it,"ok".toByteArray(),200)},store::record)
        val registry=PayloadRunRegistry(mockk())
        assertTrue(registry.results(run,0,1,false).contains("\"timingControlsFinished\":false"))
        assertTrue(run.maySend())
        timing.execute(run::maySend,{PayloadExchange(it,"limited".toByteArray(),429)},controlStore::record)
        every {audit.statusMessage()} returns "finished"
        val result=registry.results(run,0,1,false,true)
        assertTrue(result.contains("\"completed\":false"))
        assertTrue(result.contains("\"timingControlsFinished\":true"))
        assertTrue(result.contains("CONTROL_EXECUTION_STOPPED"))
        assertEquals(200,store.read(0).item.statusCode)
        assertEquals(429,controlStore.read(0).item.statusCode)
        assertTrue(result.contains("reviewReportMarkdown"))
        assertTrue(result.contains("| timing:17 |"))
        assertFalse(result.contains("responseBase64"))
        val controlFile=dir.resolve("timing-controls/0.json")
        val saved=java.nio.file.Files.readString(controlFile)
        assertTrue(saved.contains("\"statusCode\":429"))
        java.nio.file.Files.writeString(controlFile,saved.replace("\"statusCode\":429","\"statusCode\":200"))
        assertThrows(IllegalArgumentException::class.java) { registry.results(run,0,1,false,true) }
    }
    @Test fun `result pages expose grep negative triage while baseline wire remains opt in`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val directory = root.resolve("triage")
        val store = PayloadEvidenceStore.create(directory, plan)
        store.recordBaseline(PayloadExchange("private baseline request".toByteArray(), "HTTP/1.1 200 OK\r\n\r\nnormal".toByteArray(), 200))
        val execution = PayloadExecution(plan)
        val run = PayloadRunRegistry.Run("id", plan, execution, store, directory, mockk())
        val audit = mockk<Audit>()
        every { audit.statusMessage() } returns "finished"
        run.audit = audit
        execution.execute({true}, {PayloadExchange(it, "HTTP/1.1 500 Error\r\n\r\nerror".toByteArray(), 500)}, store::record)
        val registry = PayloadRunRegistry(mockk())
        val redacted = registry.results(run, 0, 1, false)
        assertTrue(redacted.contains("HTTP_SERVER_ERROR"))
        assertTrue(redacted.contains("STATUS_CHANGED"))
        assertTrue(redacted.contains("REVIEW_REQUIRED"))
        assertFalse(redacted.contains("requestBase64"))
        assertFalse(redacted.contains("scannerBaseline"))
        val wire = registry.results(run, 0, 1, true)
        assertTrue(wire.contains("scannerBaseline"))
        assertTrue(wire.contains("REVIEW_REQUIRED"))
        assertTrue(wire.contains("requestBase64"))
        val reportPage = registry.results(run, 1, 1, false, true)
        assertTrue(reportPage.contains("\"items\":[]"))
        assertTrue(reportPage.contains("reviewReportMarkdown"))
        assertTrue(reportPage.contains("HTTP_SERVER_ERROR"))
        assertTrue(reportPage.contains("\"diagnosisCompleted\":false"))
        assertTrue(reportPage.contains("EXECUTION_AND_EVIDENCE_ONLY"))
        assertFalse(reportPage.contains("private baseline request"))
        assertFalse(reportPage.contains("requestBase64"))
    }
    @Test fun `result pages reject metadata corruption even outside the selected page`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val directory = root.resolve("corrupt")
        val store = PayloadEvidenceStore.create(directory, plan)
        val execution = PayloadExecution(plan)
        val run = PayloadRunRegistry.Run("id", plan, execution, store, directory, mockk())
        val audit = mockk<Audit>()
        every { audit.statusMessage() } returns "finished"
        run.audit = audit
        execution.execute({true}, {PayloadExchange(it, "HTTP/1.1 200 OK\r\n\r\n".toByteArray(), 200)}, store::record)
        val api = mockk<MontoyaApi>()
        val registry = PayloadRunRegistry(api)
        assertTrue(registry.results(run, 0, 1, true).contains("\"completed\":true"))
        val file = directory.resolve("0.json")
        val original = java.nio.file.Files.readString(file)
        assertTrue(original.contains("\"payloadId\":\"p\""))
        java.nio.file.Files.writeString(file, original.replace("\"payloadId\":\"p\"", "\"payloadId\":\"other\""))
        for (includeWire in listOf(false,true)) {
            assertThrows(IllegalArgumentException::class.java) { registry.results(run, 0, 1, includeWire) }
            assertThrows(IllegalArgumentException::class.java) { registry.results(run, 1, 1, includeWire) }
        }
        verify { api wasNot Called }
        verify(exactly = 0) { audit.addRequest(any()) }
    }
    @Test fun `submission uncertainty prevents success even when callback evidence and native completion are present`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val store = PayloadEvidenceStore.create(root.resolve("uncertain"), plan)
        val execution = PayloadExecution(plan)
        val run = PayloadRunRegistry.Run("id", plan, execution, store, root.resolve("uncertain"), mockk())
        val audit = mockk<Audit>()
        every { audit.statusMessage() } returns "finished"
        run.audit = audit
        execution.execute({ true }, { bytes -> PayloadExchange(bytes, "HTTP/1.1 200 OK\r\n\r\n".toByteArray(), 200) }, store::record)
        run.submissionError = "IllegalStateException: acceptance unknown"
        val api = mockk<MontoyaApi>()
        val result = PayloadRunRegistry(api).results(run, 0, 50, true)
        assertTrue(result.contains("\"allCandidatesRecorded\":true"))
        assertTrue(result.contains("\"nativeCompleted\":true"))
        assertTrue(result.contains("\"completed\":false"))
        assertTrue(result.contains("submissionError"))
        assertTrue(result.contains("RESPONSE_RECEIVED"))
        verify { api wasNot Called }
    }

    @Test fun `creating unused registry never registers a check or changes native scanner`() {
        val api = mockk<MontoyaApi>()
        val registry = PayloadRunRegistry(api)
        assertTrue(registry.results("missing", 0, 50, false).contains("PAYLOAD_RUN_NOT_TRACKED"))
        verify { api wasNot Called }
    }

    @Test fun `native cancellation closes the send gate and lifecycle deregisters once`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val run = PayloadRunRegistry.Run("id", plan, PayloadExecution(plan), PayloadEvidenceStore.create(root.resolve("run"), plan), root.resolve("run"), mockk())
        val audit = mockk<Audit>()
        every { audit.statusMessage() } returns "scanning"
        run.audit = audit
        assertTrue(run.maySend())
        every { audit.statusMessage() } returns "cancelled"
        assertFalse(run.maySend())
        val registration = mockk<burp.api.montoya.core.Registration>(relaxed = true)
        run.registration = registration
        run.close(); run.close()
        verify(exactly = 1) { registration.deregister() }
        assertFalse(run.maySend())
    }

    @Test fun `invalid pagination never accesses API`() {
        val api = mockk<MontoyaApi>()
        val registry = PayloadRunRegistry(api)
        assertThrows(IllegalArgumentException::class.java) { registry.results("id", -1, 1, false) }
        assertThrows(IllegalArgumentException::class.java) { registry.results("id", 0, 101, false) }
        verify { api wasNot Called }
    }

    @Test fun `native observation failure retains pending rows and does not report completion`() {
        val plan = PayloadWirePlan.create("x=1".toByteArray(), PayloadProfileCatalog("a".repeat(64),
            listOf(ProfilePayload("p", "replace", "light", "2", listOf("query")))), "light", listOf(PayloadWirePosition("x", "query", 2, 3, 0, 1)))
        val run = PayloadRunRegistry.Run("id", plan, PayloadExecution(plan), PayloadEvidenceStore.create(root.resolve("unavailable"), plan), root.resolve("unavailable"), mockk())
        val audit = mockk<Audit>()
        every { audit.statusMessage() } throws NullPointerException("native task unavailable")
        run.audit = audit
        val api = mockk<MontoyaApi>()
        val result = kotlinx.serialization.json.Json.parseToJsonElement(PayloadRunRegistry(api).results(run, 0, 50, false)).toString()
        assertTrue(result.contains("nativeObservationError"))
        assertTrue(result.contains("\"completed\":false"))
        assertTrue(result.contains("PENDING"))
        verify { api wasNot Called }
        verify(exactly = 0) { audit.addRequest(any()) }
        verify(exactly = 0) { audit.delete() }
    }
}
