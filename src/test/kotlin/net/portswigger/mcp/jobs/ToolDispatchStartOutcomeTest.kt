package net.portswigger.mcp.jobs

import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ToolDispatchStartOutcomeTest {
    @Test fun typedProducerCannotBeCalledThroughTheManagedPublicMutationFacade() {
        val dispatch=ToolDispatch(true);var calls=0
        dispatch.registerWorkerScanStart { calls++;scanStartNotSubmitted("SCAN_START_INPUT_INVALID","INPUT_DECODING") }
        assertEquals("MANAGED_MODE_JOB_REQUIRED",assertThrows(JobRejected::class.java) { dispatch.publicCall("start_active_scan",JsonObject(emptyMap())) }.code)
        assertEquals(0,calls);assertTrue(provenNoAuditStart(dispatch.workerScanStart(JsonObject(emptyMap()))));assertEquals(1,calls)
    }
    @Test fun legacyDenialIsCompatibleButOtherTextNeverProvesNoAudit() {
        val dispatch=ToolDispatch(false)
        dispatch.register("start_active_scan") { listOf(TextContent(LEGACY_SCAN_START_DENIED)) }
        assertTrue(provenNoAuditStart(dispatch.workerScanStart(JsonObject(emptyMap()))))
        dispatch.register("start_active_scan") { listOf(TextContent("unknown reply")) }
        assertThrows(Exception::class.java) { dispatch.workerScanStart(JsonObject(emptyMap())) }
    }
    @Test fun absentHandlerIsAProvenUnsupportedPrecheckWithoutNativeCalls() {
        val result=ToolDispatch(true).workerScanStart(JsonObject(emptyMap()))
        assertTrue(provenNoAuditStart(result));assertEquals(JsonPrimitive("SCAN_START_UNSUPPORTED"),result["errorCode"])
    }
}
