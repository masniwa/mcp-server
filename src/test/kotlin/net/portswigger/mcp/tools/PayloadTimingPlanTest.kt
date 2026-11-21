package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadTimingPlanTest {
    private val request="GET /test?x=normal&keep=1 HTTP/1.1\r\nHost: 192.168.56.66\r\n\r\n".toByteArray()
    private val position=PayloadWirePosition("query:x","query",12,18,10,11)
    private val options=PayloadTimingControls("query:x",listOf(PayloadTimingLevel(1000,"true 1","false 1"),PayloadTimingLevel(3000,"true 3","false 3")))
    @Test fun `control values change only selected parameter with contextual encoding`() {
        val c=prepareTimingCollection(request,listOf(position),options)
        val sent=mutableListOf<String>()
        c.execute({true},{sent+=it.toString(Charsets.UTF_8);PayloadExchange(it,"ok".toByteArray(),200)},{_,_->})
        assertEquals(18,sent.size)
        assertEquals(request.toString(Charsets.UTF_8),sent[0])
        assertEquals("GET /test?x=true%201&keep=1 HTTP/1.1\r\nHost: 192.168.56.66\r\n\r\n",sent[1])
        assertEquals("GET /test?x=false%201&keep=1 HTTP/1.1\r\nHost: 192.168.56.66\r\n\r\n",sent[2])
    }
    @Test fun `unknown method raw array and unresolved control plans fail before sending`() {
        assertThrows(IllegalStateException::class.java) {prepareTimingCollection(request,listOf(position),options.copy(positionId="other"))}
        assertThrows(IllegalArgumentException::class.java) {prepareTimingCollection(request,listOf(position),options.copy(mode="array"))}
        assertThrows(IllegalArgumentException::class.java) {prepareTimingCollection(request,listOf(position.copy(target="method")),options)}
        assertThrows(IllegalArgumentException::class.java) {prepareTimingCollection(request,listOf(position.copy(context="raw")),options)}
        assertThrows(IllegalArgumentException::class.java) {prepareTimingCollection(request,listOf(position),options.copy(levels=listOf(PayloadTimingLevel(1000,"__UNBOUND__","false"),options.levels[1])))}
    }
}
