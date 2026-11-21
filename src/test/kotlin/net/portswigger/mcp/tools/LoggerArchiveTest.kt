package net.portswigger.mcp.tools

import net.portswigger.mcp.schema.HttpService
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.util.regex.Pattern

class LoggerArchiveTest {
    @TempDir lateinit var directory:Path
    private val service=HttpService("fixture.invalid",8080,false)
    @Test fun `disk evidence survives memory eviction and correlates a delayed response without reload`() {
        LoggerHttpHistory(maxEntries=3,maxBytes=4096,archiveDirectory=directory).use { h ->
            val original=h.status().captureId
            repeat(30) { h.recordRequest(it,"SCANNER",service,"http://fixture.invalid:8080/$it","request-$it",null) }
            h.recordResponse(0,"SCANNER",service,"http://fixture.invalid:8080/0","actual-request-0","response-0",null)
            val status=h.status()
            assertEquals(original,status.captureId);assertEquals(30,status.retainedEntries)
            assertEquals(0,status.droppedEntries);assertEquals(0,status.captureErrors);assertEquals("DISK",status.storageMode)
            assertTrue(status.memoryEntries<=3);assertTrue(status.memoryBytes<=4096);assertTrue(status.memoryEvictedEntries>0)
            val first=h.lookup(1,LoggerRequestIdType.MCP_CAPTURE_ID,original).logger!!
            assertEquals("actual-request-0",first.request);assertEquals("response-0",first.response)
            assertEquals((11L..15L).toList(),h.page(5,0,10,15).map { it.id })
            assertEquals(listOf(21L,22L),h.page(2,0,regex=Pattern.compile("request-2[01]$")).map { it.id })
        }
    }
    @Test fun `oversized messages are archived whole and pending helpers stay observable`() {
        LoggerHttpHistory(maxEntries=1,maxBytes=600,archiveDirectory=directory).use { h ->
            val text="request-"+"x".repeat(2000)
            h.recordRequest(1,"EXTENSIONS",service,"http://fixture.invalid:8080/",text,null)
            assertFalse(h.quiescent(setOf(service)))
            h.recordResponse(1,"EXTENSIONS",service,"http://fixture.invalid:8080/",text,"response-"+"y".repeat(2000),null)
            assertTrue(h.quiescent(setOf(service)))
            assertEquals(text,h.page(1,0).single().request)
            assertEquals(0,h.status().droppedEntries);assertEquals(0,h.status().memoryEntries)
        }
    }
    @Test fun `storage outage is reported instead of empty successful evidence or a reload workaround`() {
        val h=LoggerHttpHistory(archiveDirectory=directory);h.close()
        h.recordRequest(1,"SCANNER",service,"http://fixture.invalid:8080/","request",null)
        val status=h.status()
        assertTrue(status.captureErrors>0);assertEquals("DISK_ERROR",status.storageMode)
        assertThrows(Exception::class.java) { h.page(1,0) }
    }
}
