package net.portswigger.mcp.tools

import burp.api.montoya.core.Range
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.Audit
import io.mockk.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class AuditParameterSelectionTest {
    private fun parameter(name: String, start: Int, end: Int, type: HttpParameterType = HttpParameterType.JSON): ParsedHttpParameter {
        val range = mockk<Range>()
        every { range.startIndexInclusive() } returns start
        every { range.endIndexExclusive() } returns end
        return mockk { every { name() } returns name; every { type() } returns type; every { valueOffsets() } returns range }
    }
    @Test fun `selected JSON values exclude password cookie and other locations`() {
        val points = listOf(parameter("password", 90, 96), parameter("name", 110, 116), parameter("name", 130, 136, HttpParameterType.COOKIE))
        val result = selectAuditParameters(points, listOf(AuditParameterSelector("name", "JSON")), 200)
        assertEquals(listOf(110), result.map { it.startIndexInclusive() })
    }
    @Test fun `same name occurrences are all included in wire order`() {
        val result = selectAuditParameters(listOf(parameter("x",30,32), parameter("x",10,12)), listOf(AuditParameterSelector("x","JSON")), 40)
        assertEquals(listOf(10,30),result.map { it.startIndexInclusive() })
    }
    @Test fun `missing names and wrong case types do not fall back to automatic`() {
        for (selector in listOf(AuditParameterSelector("absent","JSON"),AuditParameterSelector("x","json"))) {
            assertThrows(IllegalArgumentException::class.java) { selectAuditParameters(listOf(parameter("x",10,12)), listOf(selector),40) }
        }
    }
    @Test fun `empty duplicate and excessive selections are refused`() {
        for (selectors in listOf(emptyList(),List(2){AuditParameterSelector("x","JSON")},List(129){AuditParameterSelector("x$it","JSON")})) {
            assertThrows(IllegalArgumentException::class.java) { selectAuditParameters(listOf(parameter("x",10,12)),selectors,40) }
        }
    }
    @Test fun `invalid empty and overlapping ranges are refused`() {
        for ((a,b) in listOf(-1 to 2,10 to 10,10 to 50)) {
            assertThrows(IllegalArgumentException::class.java) { selectAuditParameters(listOf(parameter("x",a,b)),listOf(AuditParameterSelector("x","JSON")),40) }
        }
        assertThrows(IllegalArgumentException::class.java) { selectAuditParameters(listOf(parameter("x",10,20),parameter("x",15,25)),listOf(AuditParameterSelector("x","JSON")),40) }
    }
    @Test fun `explicit selection uses only range overload and omitted selection preserves original behavior`() {
        val audit=mockk<Audit>(relaxed=true);val request=mockk<HttpRequest>();val point=mockk<Range>()
        addSelectedAuditRequest(audit,request,listOf(point))
        verify(exactly=1) { audit.addRequest(request,listOf(point)) };verify(exactly=0) { audit.addRequest(request) }
        clearMocks(audit);addSelectedAuditRequest(audit,request,null)
        verify(exactly=1) { audit.addRequest(request) };verify(exactly=0) { audit.addRequest(request,any()) }
    }
}
