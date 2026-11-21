package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.*
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class NativeRequestMetadataTest {
    @Test fun `multipart filename uses exact native selector and offsets without leaking its value`() {
        val p=mockk<ParsedHttpParameter>()
        every { p.name() } returns "observed-filename"
        every { p.type() } returns HttpParameterType.MULTIPART_ATTRIBUTE
        val range=mockk<Range>()
        every { range.startIndexInclusive() } returns 100;every { range.endIndexExclusive() } returns 108
        every { p.valueOffsets() } returns range
        val result=nativeParameterMetadata(listOf(p),500).single()
        assertEquals("observed-filename",result.name);assertEquals("MULTIPART_ATTRIBUTE",result.type)
        assertEquals(100,result.valueStart);assertEquals(108,result.valueEnd);assertTrue(result.valueSelectable)
        verify(exactly=0) { p.value() }
    }
    @Test fun `empty and invalid native values are visible but not represented as selectable`() {
        val p=mockk<ParsedHttpParameter>()
        every { p.name() } returns "empty";every { p.type() } returns HttpParameterType.BODY
        val range=mockk<Range>()
        every { range.startIndexInclusive() } returns 10;every { range.endIndexExclusive() } returns 10
        every { p.valueOffsets() } returns range
        assertFalse(nativeParameterMetadata(listOf(p),100).single().valueSelectable)
    }
}
