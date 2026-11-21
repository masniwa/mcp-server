package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeStartOutcomeTest {
    @Test fun publicSummaryRetainsCauseAndDigestWithoutNativeMessagesOrUnexpectedFields() {
        val raw=JsonObject(scanStartNotSubmitted("SCAN_START_REJECTED","PRECHECK","IllegalArgumentException")+mapOf(
            "message" to JsonPrimitive("private-detail"),"submissionError" to JsonPrimitive("private-detail")))
        val summary=scanStartSummary(raw)
        assertEquals(JsonPrimitive("PRECHECK"),summary["stage"]);assertEquals(JsonPrimitive(fingerprint(raw)),summary["responseDigest"])
        assertEquals(JsonPrimitive(true),summary["submissionErrorObserved"]);assertFalse(summary.toString().contains("private-detail"))
    }
    @Test fun producerPreAuditRejectionsHaveCompleteProof() {
        for(stage in listOf("INPUT_DECODING","PRECHECK","PERMISSION_CHECK","REQUEST_PREPARATION","PAYLOAD_PREPARATION"))
            assertTrue(provenNoAuditStart(scanStartNotSubmitted("SCAN_START_REJECTED",stage)))
        assertThrows(JobRejected::class.java) { scanStartNotSubmitted("SCAN_START_REJECTED","NATIVE_AUDIT_CREATION") }
    }
    @Test fun incompleteContradictoryOrCallerShapedProofNeverBecomesNoAudit() {
        val valid=scanStartNotSubmitted("SCAN_START_REJECTED","PRECHECK")
        for(result in listOf(JsonObject(valid-"nativeAuditCreated"),JsonObject(valid-"submissionAttempted"),
            JsonObject(valid+("nativeAuditCreated" to JsonPrimitive(true))),JsonObject(valid+("submissionAttempted" to JsonPrimitive("false"))),
            JsonObject(valid+("submissionError" to JsonPrimitive("unknown acceptance"))),JsonObject(valid+("observationError" to JsonPrimitive("native observation failed"))),
            JsonObject(valid+("nativeCompleted" to JsonPrimitive(true))),JsonObject(valid+("completed" to JsonObject(emptyMap()))),
            JsonObject(valid+("auditId" to JsonPrimitive("audit"))),JsonObject(valid+("stage" to JsonPrimitive("UNKNOWN"))),
            JsonObject(valid+("errorCode" to JsonPrimitive("untrusted free text"))),JsonObject(valid+("errorCode" to JsonObject(emptyMap())))))
            assertFalse(provenNoAuditStart(result))
    }
}
