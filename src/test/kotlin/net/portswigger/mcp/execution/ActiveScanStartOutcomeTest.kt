package net.portswigger.mcp.execution

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import io.mockk.*
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.tools.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

class ActiveScanStartOutcomeTest {
    @Test fun postSubmissionLinkageFailureRetainsAcceptanceAndHandle() {
        every { api.logging().logToOutput(match<String> { it.contains("submission returned") }) } throws NoSuchMethodError("unsupported SDK")
        val outcome=start.startManaged(input,config)
        assertEquals(JsonPrimitive("submitted_status_unavailable"),outcome["status"])
        assertNotNull(outcome["auditId"]);assertEquals(JsonPrimitive(4),outcome["auditRequestCount"])
        verify(exactly=1) { native.addRequest(request) }
    }
    @Test fun unavailableSdkMethodsKeepPartialMetricsAndUnknownSubmission() {
        every { native.statusMessage() } throws NoSuchMethodError("unsupported status")
        every { native.errorCount() } throws AbstractMethodError("unsupported metric")
        every { native.addRequest(request) } throws NoSuchMethodError("acceptance unknown")
        val outcome=start.startManaged(input,config)
        assertEquals(JsonPrimitive("submission_outcome_unknown"),outcome["status"])
        val id=outcome.getValue("auditId").jsonPrimitive.content
        val snapshot=registry.snapshot(id)!!
        assertEquals(JsonPrimitive(4),snapshot["auditRequestCount"])
        assertEquals(JsonNull,snapshot["auditErrorCount"]);assertEquals(JsonNull,snapshot["completed"])
        assertNotNull(snapshot["submissionError"]);assertNotNull(snapshot["observationError"])
        assertFalse(provenNoAuditStart(outcome));verify(exactly=1) { native.addRequest(request) }
    }
    @Test fun fatalVmErrorsAreNotConvertedIntoRecoveryProof() {
        every { api.scanner().startAudit(auditConfig) } throws OutOfMemoryError("fixture only")
        assertThrows(OutOfMemoryError::class.java) { start.startManaged(input,config) }
    }
    @Test fun unavailableScannerServiceDoesNotBecomeAnAttemptedAuditCreation() {
        every { api.scanner() } throws UnsupportedOperationException("service unavailable")
        val outcome=start.startManaged(input,config)
        assertTrue(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("SCAN_START_SCANNER_SERVICE_UNAVAILABLE"),outcome["errorCode"])
        verify(exactly=0) { native.addRequest(any<HttpRequest>()) }
    }
    private val api=mockk<MontoyaApi>(relaxed=true)
    private val config=mockk<McpConfig>(relaxed=true)
    private val native=mockk<Audit>(relaxed=true)
    private val request=mockk<HttpRequest>(relaxed=true)
    private val service=mockk<HttpService>()
    private val auditConfig=mockk<AuditConfiguration>()
    private val payloads=mockk<PayloadRunRegistry>(relaxed=true)
    private val registry=ActiveAuditRegistry()
    private val start=ActiveScanService(api,registry,payloads)
    private val input=StartActiveScan("GET / HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n","fixture.invalid",80,"http")
    @BeforeEach fun setup() {
        mockkObject(HttpRequestSecurity)
        coEvery { HttpRequestSecurity.checkHttpRequestPermission(any(),any(),any(),any(),any()) } returns true
        mockkStatic(HttpService::class,HttpRequest::class,AuditConfiguration::class)
        every { HttpService.httpService(any<String>(),any<Int>(),any<Boolean>()) } returns service
        every { HttpRequest.httpRequest(service,any<String>()) } returns request
        every { request.parameters() } returns emptyList()
        every { request.method() } returns "GET"
        every { AuditConfiguration.auditConfiguration(any()) } returns auditConfig
        every { api.scanner().startAudit(auditConfig) } returns native
        every { native.statusMessage() } returns "scanning"
        every { native.requestCount() } returns 4
        every { native.insertionPointCount() } returns 2
        every { native.errorCount() } returns 0
    }
    @AfterEach fun cleanup() { unmockkObject(HttpRequestSecurity);unmockkStatic(HttpService::class,HttpRequest::class,AuditConfiguration::class) }
    @Test fun permissionDenialPreservesLegacyAndProvidesManagedNoAuditProof() {
        coEvery { HttpRequestSecurity.checkHttpRequestPermission(any(),any(),any(),any(),any()) } returns false
        assertEquals(LEGACY_SCAN_START_DENIED,start.start(input,config))
        val outcome=start.startManaged(input,config)
        assertTrue(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("SCAN_START_PERMISSION_DENIED"),outcome["errorCode"])
        every { api.logging().logToOutput(any<String>()) } throws IllegalStateException("private-log-failure")
        val loggingFailure=start.startManaged(input,config)
        assertEquals(JsonPrimitive("SCAN_START_PERMISSION_DENIED"),loggingFailure["errorCode"])
        assertTrue(provenNoAuditStart(loggingFailure));assertFalse(loggingFailure.toString().contains("private-log-failure"))
        verify(exactly=0) { api.scanner().startAudit(any()) }
    }
    @Test fun precheckAndRequestPreparationErrorsRemainBeforeAuditAndDoNotExposeMessages() {
        val invalid=input.copy(etaProfile="invalid secret value")
        val outcome=start.startManaged(invalid,config)
        assertTrue(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("PRECHECK"),outcome["stage"])
        assertEquals(JsonPrimitive("INVALID_SCAN_ETA_PROFILE"),outcome["errorCode"])
        assertFalse(outcome.toString().contains("invalid secret value"))
        assertThrows(IllegalArgumentException::class.java) { start.start(invalid,config) }
        every { HttpService.httpService(any<String>(),any<Int>(),any<Boolean>()) } throws IllegalArgumentException("private detail")
        val preparation=start.startManaged(input,config)
        assertTrue(provenNoAuditStart(preparation));assertEquals(JsonPrimitive("REQUEST_PREPARATION"),preparation["stage"])
        assertFalse(preparation.toString().contains("private detail"));verify(exactly=0) { api.scanner().startAudit(any()) }
    }
    @Test fun enteringNativeCreationCannotProveNoAuditEvenWithoutAHandle() {
        every { api.scanner().startAudit(auditConfig) } throws IllegalStateException("unknown native effect")
        val outcome=start.startManaged(input,config)
        assertFalse(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("submission_outcome_unknown"),outcome["status"])
        assertNull(outcome["auditId"]);assertEquals(JsonNull,outcome["nativeAuditCreated"])
        verify(exactly=1) { api.scanner().startAudit(any()) };verify(exactly=0) { native.addRequest(any<HttpRequest>()) }
    }
    @Test fun uncertainAddRequestRetainsHandleAndNeverTurnsIntoAcceptedObservation() {
        every { native.addRequest(request) } throws IllegalStateException("acceptance unknown")
        val outcome=start.startManaged(input,config)
        assertFalse(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("submission_outcome_unknown"),outcome["status"])
        assertNotNull(outcome["auditId"]);assertNotNull(outcome["submissionError"])
        verify(exactly=1) { native.addRequest(request) }
    }
    @Test fun postSubmissionLoggingFailureRetainsKnownAcceptanceHandleAndPartialMetrics() {
        every { api.logging().logToOutput(match<String> { it.contains("submission returned") }) } throws IllegalStateException("private detail")
        val outcome=start.startManaged(input,config)
        assertEquals(JsonPrimitive("submitted_status_unavailable"),outcome["status"]);assertNotNull(outcome["auditId"])
        assertEquals(JsonPrimitive(4),outcome["auditRequestCount"]);assertFalse(outcome.toString().contains("private detail"))
        verify(exactly=1) { native.addRequest(request) }
    }
    @Test fun initialStatusFailureAfterAcceptanceRetainsTheSameNativeHandle() {
        every { native.statusMessage() } throws IllegalStateException("temporary observation failure")
        val outcome=start.startManaged(input,config)
        assertEquals(JsonPrimitive("submitted_status_unavailable"),outcome["status"]);assertNotNull(outcome["auditId"])
        assertEquals(JsonPrimitive(0),outcome["auditErrorCount"])
        verify(exactly=1) { native.addRequest(request) }
    }
    @Test fun cleanupFailureNeverReplacesTheFirstNativeFailureOrProvesNoAudit() {
        val run=mockk<PayloadRunRegistry.Run>(relaxed=true)
        every { run.id } returns "payload-fixture"
        every { run.scanRequest } returns request
        every { run.close() } throws IllegalStateException("private cleanup failure")
        every { payloads.prepare(request,null,any()) } returns run
        every { api.scanner().startAudit(auditConfig) } throws IllegalArgumentException("first private failure")
        val outcome=start.startManaged(input.copy(payloadProfile=mockk(relaxed=true)),config)
        assertEquals(JsonPrimitive("submission_outcome_unknown"),outcome["status"]);assertFalse(provenNoAuditStart(outcome))
        assertEquals(JsonPrimitive("IllegalArgumentException"),outcome["causeClass"])
        assertEquals(JsonPrimitive("IllegalStateException"),outcome["cleanupErrorClass"])
        assertFalse(outcome.toString().contains("private"));verify(exactly=0) { native.addRequest(any<HttpRequest>()) }
    }
    @Test fun preAuditLocalCleanupFailureIsSeparateFromKnownNativeNonCreation() {
        val run=mockk<PayloadRunRegistry.Run>(relaxed=true)
        every { run.id } returns "payload-fixture"
        every { run.scanRequest } throws IllegalArgumentException("first private preparation failure")
        every { run.close() } throws IllegalStateException("private cleanup failure")
        every { payloads.prepare(request,null,any()) } returns run
        val outcome=start.startManaged(input.copy(payloadProfile=mockk(relaxed=true)),config)
        assertTrue(provenNoAuditStart(outcome));assertEquals(JsonPrimitive("PAYLOAD_PREPARATION"),outcome["stage"])
        assertEquals(JsonPrimitive("UNVERIFIED"),outcome["localPreparationCleanup"])
        assertEquals(JsonPrimitive("IllegalArgumentException"),outcome["causeClass"])
        assertEquals(JsonPrimitive("IllegalStateException"),outcome["cleanupErrorClass"])
        assertFalse(outcome.toString().contains("private"));verify(exactly=0) { api.scanner().startAudit(any()) }
    }
}
