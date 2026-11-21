package net.portswigger.mcp.tools

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PayloadTimingCollectionTest {
    private fun inputs()=listOf(1000L,3000L).map { TimingControlInput(it,"normal".toByteArray(),"true:$it".toByteArray(),"false:$it".toByteArray()) }
    @Test fun `interleaved controls alternate ordering and preserve exact evidence`() {
        var now=0L; val input=inputs(); val collector=PayloadTimingCollection(input,3) { now }
        input[0].conditionTrue.fill(0) // caller mutation cannot change prepared sequence
        val sent=mutableListOf<String>(); val records=mutableListOf<PayloadExecutionItem>()
        collector.execute({now+=1_000_000_000;true},{ bytes ->
            val value=bytes.toString(Charsets.UTF_8); sent+=value
            now+=(100L+if(value.startsWith("true:")) value.substringAfter(':').toLong() else 0L)*1_000_000
            PayloadExchange(bytes,"ok".toByteArray(),200,bytes)
        },{ row,_ -> records+=row; now+=2_000_000_000 })
        assertEquals(listOf("normal","true:1000","false:1000","normal","true:3000","false:3000",
            "false:3000","true:3000","normal","false:1000","true:1000","normal"),sent.take(12))
        assertEquals(18,records.size)
        assertEquals("REPRODUCIBLE_DELAY_PATTERN",collector.comparison("context","run").state)
        assertFalse(collector.execute({true},{error("no replay")},{_,_->}))
    }
    @Test fun `rate limit stops subsequent controls without losing planned rows`() {
        val collector=PayloadTimingCollection(inputs())
        collector.execute({true},{PayloadExchange(it,"limited".toByteArray(),429)},{_,_->})
        assertEquals(1,collector.snapshot().count {it.state=="RESPONSE_RECEIVED"})
        assertEquals(17,collector.snapshot().count {it.state=="NOT_SENT"})
        assertEquals("INSUFFICIENT_EVIDENCE",collector.comparison("context","run").state)
    }
    @Test fun `no response and commit failure stop without replay`() {
        for (failure in listOf("transport","commit","empty")) {
            val collector=PayloadTimingCollection(inputs())
            collector.execute({true},{if(failure=="transport") error("transport"); PayloadExchange(it,if(failure=="empty")null else "ok".toByteArray(),if(failure=="empty")null else 200)},
                {_,_->if(failure=="commit") error("commit")})
            assertEquals(17,collector.snapshot().count {it.state=="NOT_SENT"})
            assertEquals("INSUFFICIENT_EVIDENCE",collector.comparison("context","run").state)
        }
    }
}
