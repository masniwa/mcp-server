package net.portswigger.mcp.tools

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import net.portswigger.mcp.schema.HttpService
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class LoggerSendCompletionTest {
    @Test fun `response gaps do not become current send activity or capture loss`() {
        LoggerHttpHistory().use { history ->
            val checkpoint = history.status()
            repeat(4) { index -> request(history, index + 1, tool = "SCANNER") }
            val observation = history.recoveryObservation(checkpoint)
            assertEquals(JsonPrimitive(4L),observation["responseGapCount"])
            assertTrue(observation["responseGaps"].toString().contains("UNVERIFIED_USE_SAVED_EXECUTION_EVIDENCE"))
            assertFalse(observation["responseGaps"].toString().contains(raw))
            assertEquals(JsonPrimitive(0), observation["activeTrackedMcpSends"])
            assertEquals(JsonPrimitive("NO_WINDOW_LOSS_OBSERVED"), observation["captureHealth"])
            assertEquals(JsonPrimitive("UNVERIFIED"), observation["nativeAndHelperStop"])
            assertTrue(history.snapshot().all { it.responseState == "NO_RESPONSE_OBSERVED" })
            val token = history.beginSend(service, raw)
            assertEquals(JsonPrimitive(1), history.recoveryObservation(checkpoint)["activeTrackedMcpSends"])
            history.endSend(token, null, null)
            assertEquals(JsonPrimitive(0), history.recoveryObservation(checkpoint)["activeTrackedMcpSends"])
        }
    }

    @Test fun `old capture loss is separate from loss in current observation window`() {
        LoggerHttpHistory(maxBytes = 400).use { history ->
            request(history, 1, text = raw + "x".repeat(2000))
            val checkpoint = history.status()
            assertTrue(checkpoint.droppedEntries > 0)
            val before = history.recoveryObservation(checkpoint)
            assertEquals(JsonPrimitive(checkpoint.droppedEntries), before["historicalDroppedEntries"])
            assertEquals(JsonPrimitive(0L), before["windowDroppedEntries"])
            assertEquals(JsonPrimitive("NO_WINDOW_LOSS_OBSERVED"), before["captureHealth"])
            request(history, 2, text = raw + "x".repeat(2000))
            assertEquals(JsonPrimitive("WINDOW_INCOMPLETE"), history.recoveryObservation(checkpoint)["captureHealth"])
            assertEquals(JsonPrimitive("UNVERIFIED"), history.recoveryObservation(null)["captureHealth"])
            assertEquals(JsonPrimitive(false), history.recoveryObservation(checkpoint.copy(captureId = "different"))["checkpointValid"])
        }
    }

    @TempDir lateinit var directory:Path
    private val service=HttpService("fixture.invalid",8080,false)
    private val raw="GET /read HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n"
    private fun request(h:LoggerHttpHistory,id:Int=1,text:String=raw,tool:String="EXTENSIONS") =
        h.recordRequest(id,tool,service,"http://fixture.invalid:8080/read",text,null)

    @Test fun `returned send without response is quiescent while its response evidence remains absent`() {
        for(disk in listOf(false,true)) LoggerHttpHistory(archiveDirectory=directory.resolve("return-$disk").takeIf { disk }).use { h ->
            val token=h.beginSend(service,raw)
            assertFalse(h.quiescent(setOf(service))) // Even before the request handler runs.
            request(h);assertFalse(h.quiescent(setOf(service)))
            h.endSend(token,service,raw)
            assertTrue(h.quiescent(setOf(service)))
            val item=h.page(1,0).single()
            assertEquals("NO_RESPONSE_OBSERVED",item.responseState)
            assertNull(item.response);assertNull(item.responseTime)
            assertEquals("SEND_RETURNED",item.sendCompletionState);assertNotNull(item.sendCompletionTime)
            assertEquals(raw,item.request);assertEquals(1,h.status().retainedEntries)
        }
    }

    @Test fun `capture status counts tracked MCP sends independently of response evidence`() {
        LoggerHttpHistory().use { history ->
            request(history, 1, tool = "SCANNER")
            val initial = history.status()
            fun trackedCount(status: LoggerHistoryStatus) = Json.parseToJsonElement(
                Json.encodeToString(LoggerHistoryStatus.serializer(), status)
            ).jsonObject["activeTrackedMcpSends"]

            assertEquals(JsonPrimitive(0), trackedCount(initial))
            val token = history.beginSend(service, raw)
            assertEquals(JsonPrimitive(1), trackedCount(history.status()))
            history.endSend(token, null, null)
            val after = history.status()
            assertEquals(JsonPrimitive(0), trackedCount(after))
            val item = history.page(1, 0).single()
            assertEquals("NO_RESPONSE_OBSERVED", item.responseState)
            assertNull(item.sendCompletionState)
            assertFalse(history.quiescent(setOf(service)))
        }
    }

    @Test fun `overlapping identical sends cannot complete another send by matching its URL or body`() {
        LoggerHttpHistory().use { h ->
            val a=h.beginSend(service,raw);val b=h.beginSend(service,raw)
            request(h,1);request(h,2)
            h.endSend(a,service,raw);h.endSend(b,service,raw)
            assertFalse(h.quiescent(setOf(service)))
            assertTrue(h.snapshot().all { it.sendCompletionState==null })
        }
    }

    @Test fun `an older unresolved helper remains a blocker after a later send returns`() {
        LoggerHttpHistory().use { h ->
            request(h,1)
            val token=h.beginSend(service,raw);request(h,2);h.endSend(token,service,raw)
            assertFalse(h.quiescent(setOf(service)))
            assertNull(h.snapshot().first().sendCompletionState)
            assertEquals("SEND_RETURNED",h.snapshot().last().sendCompletionState)
        }
    }
    @Test fun `unverified maintenance checks only new capture traffic but never ignores a live send`() {
        for(disk in listOf(false,true)) LoggerHttpHistory(archiveDirectory=directory.resolve("checkpoint-$disk").takeIf { disk }).use { h ->
            request(h,1,tool="SCANNER")
            val checkpoint=h.status()
            assertFalse(h.quiescent(setOf(service)))
            assertTrue(h.quiescentAfter(setOf(service),checkpoint.captureId,checkpoint.latestId))
            val active=h.beginSend(service,raw)
            assertFalse(h.quiescentAfter(setOf(service),checkpoint.captureId,checkpoint.latestId))
            request(h,2)
            h.endSend(active,service,raw)
            assertTrue(h.quiescentAfter(setOf(service),checkpoint.captureId,checkpoint.latestId))
            request(h,3,tool="SCANNER")
            assertFalse(h.quiescentAfter(setOf(service),checkpoint.captureId,checkpoint.latestId))
            assertFalse(h.quiescentAfter(setOf(service),"wrong-capture",checkpoint.latestId))
        }
    }

    @Test fun `exceptional return modified request mismatched service and non-extension traffic remain unresolved`() {
        val cases=listOf<Pair<HttpService?,String?>>(null to null,service to "$raw changed",service.copy(port=8081) to raw)
        cases.forEachIndexed { i,result -> LoggerHttpHistory(archiveDirectory=directory.resolve("unmatched-$i")).use { h ->
            val token=h.beginSend(service,raw);request(h)
            h.endSend(token,result.first,result.second)
            assertFalse(h.quiescent(setOf(service)));assertNull(h.page(1,0).single().sendCompletionState)
        } }
        LoggerHttpHistory().use { h ->
            val token=h.beginSend(service,raw);request(h,tool="SCANNER");h.endSend(token,service,raw)
            assertFalse(h.quiescent(setOf(service)))
        }
    }

    @Test fun `macro traffic in the call window is not inferred to have finished with the outer send`() {
        LoggerHttpHistory().use { h ->
            val token=h.beginSend(service,raw);request(h);request(h,2,"GET /macro HTTP/1.1\r\n\r\n")
            h.endSend(token,service,raw)
            assertFalse(h.quiescent(setOf(service)));assertTrue(h.snapshot().all { it.sendCompletionState==null })
        }
    }

    @Test fun `disk eviction and delayed response preserve both completion and message correlation`() {
        LoggerHttpHistory(maxEntries=1,maxBytes=600,archiveDirectory=directory).use { h ->
            val large=raw+"x".repeat(2000)
            val token=h.beginSend(service,large);request(h,text=large);h.endSend(token,service,large)
            assertEquals(0,h.status().memoryEntries);assertTrue(h.quiescent(setOf(service)))
            h.recordResponse(1,"EXTENSIONS",service,"http://fixture.invalid:8080/read",large,"HTTP/1.1 200 OK\r\n\r\nok",null)
            val item=h.page(2,0).single()
            assertEquals(1,item.messageId);assertEquals("RESPONSE_RECEIVED",item.responseState)
            assertEquals("SEND_RETURNED",item.sendCompletionState);assertNotNull(item.responseTime)
            assertTrue(h.quiescent(setOf(service)));assertEquals(0,h.status().captureErrors)
        }
    }

    @Test fun `missing capture and lost evidence never manufacture a completed history item`() {
        LoggerHttpHistory().use { h ->
            val token=h.beginSend(service,raw);h.endSend(token,service,raw)
            assertTrue(h.snapshot().isEmpty())
        }
        LoggerHttpHistory(maxEntries=1).use { h ->
            val token=h.beginSend(service,raw);request(h);request(h,2);h.endSend(token,service,raw)
            assertFalse(h.quiescent(setOf(service)));assertNull(h.snapshot().single().sendCompletionState)
        }
        val h=LoggerHttpHistory(archiveDirectory=directory.resolve("closed"));val token=h.beginSend(service,raw)
        h.close();request(h);h.endSend(token,service,raw)
        assertFalse(h.quiescent(setOf(service)));assertTrue(h.status().captureErrors>0)
    }
}
