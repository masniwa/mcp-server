package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeTerminationTest {
    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    @Test fun unknownSubmissionCanHaveProvenNativeTerminationWithoutBecomingSuccessfulDiagnosis() {
        val observation=obj("""{"auditId":"retained","auditStatusMessage":"finished","completed":null,"nativeCompleted":true,"submissionError":"acceptance unknown"}""")
        assertTrue(nativeExecutionTerminal(observation))
        assertEquals(JsonNull,observation["completed"])
        assertNotNull(observation["submissionError"])
        assertTrue(retainedNativeInventoryStopped(buildJsonObject { put("success",true);put("audits",JsonArray(listOf(observation))) }))
    }
    @Test fun countersElapsedTimeAndMissingStatusNeverProveTermination() {
        for(observation in listOf(
            obj("""{"auditId":"unknown","completed":null,"nativeCompleted":null,"auditRequestCount":0}"""),
            obj("""{"auditId":"unknown","completed":null,"nativeCompleted":true,"observationError":"status failed"}"""),
            obj("""{"auditId":"running","completed":false,"auditStatusMessage":"scanning"}""")
        )) assertFalse(nativeExecutionTerminal(observation))
        assertFalse(retainedNativeInventoryStopped(obj("""{"success":false,"audits":[]}""")))
        assertFalse(retainedNativeInventoryStopped(obj("""{"success":true}""")))
        assertFalse(retainedNativeInventoryStopped(obj("""{"success":true,"audits":[{"completed":true}]}""")))
    }
}