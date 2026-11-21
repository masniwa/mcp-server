package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LoggerCaptureWindowTest {
    private fun status(latest:Long=10,errors:Long=4,dropped:Long=2,capture:String="capture")=buildJsonObject {
        put("captureId",capture);put("latestId",latest);put("captureErrors",errors);put("droppedEntries",dropped)
    }
    @Test fun historicalLossIsPreservedWithoutContaminatingNewWindow() {
        val before=status();val after=status(latest=12)
        val window=loggerCaptureWindow(before,after)
        assertTrue(loggerCaptureWindowHealthy(window));assertEquals(before,window["before"]);assertEquals(after,window["after"])
        assertTrue(loggerCaptureWindowHealthy(before,before))
    }
    @Test fun captureChangesNewLossCounterRollbackAndMalformedMetadataRemainUnverified() {
        val before=status()
        for(after in listOf(status(errors=5),status(dropped=3),status(errors=3),status(latest=9),status(capture="other"),
            status(errors=-1),JsonObject(status()-"captureErrors"),JsonObject(status()+("latestId" to JsonObject(emptyMap()))),
            JsonObject(status()+("captureErrors" to JsonPrimitive("4")))))
            assertFalse(loggerCaptureWindowHealthy(before,after))
        assertFalse(loggerCaptureWindowHealthy(null))
        assertFalse(loggerCaptureWindowHealthy(buildJsonObject { put("captureHealth","NO_WINDOW_LOSS_OBSERVED") }))
    }
}
