package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class LoggingDependencyTest {
    private val options=digest("options")
    private fun snapshot(name:String=options,value:JsonElement=JsonPrimitive(3))=BurpSnapshot("instance",JsonObject(emptyMap()),
        buildJsonObject { put(name,buildJsonObject { put("verbosity",value);put("enabled",true);put("chkbox_scanner",true) }) },listOf(name),emptySet(),projectMarker="project")
    private fun plan(base:BurpSnapshot,owned:BurpSnapshot?=null):CompiledPlan {
        val endpoint=Endpoint("http","fixture.invalid",80,"/")
        val variant=ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,"request","source","hash"),settings=SettingsPlan())
        val proposal=JobProposal(jobId="logging",revision=1,objective="logging dependency",targetPolicy=emptyList(),materials=emptyList(),
            session=SessionPlan(false,"OMIT","fixture","none"),variants=listOf(variant),requiredCapabilities=emptySet(),cleanupPolicy="none")
        val target=owned ?: base
        return CompiledPlan(proposal,"proposal","plan",base,listOf(CompiledVariant(variant,target.project,target.cph,target.cphOrder,"settings")),listOf(endpoint))
    }
    private fun edit(base:BurpSnapshot,name:String,field:String,value:JsonElement?):BurpSnapshot {
        val tab=base.cph.getValue(name).jsonObject
        return base.copy(cph=JsonObject(base.cph+(name to JsonObject(if(value==null) tab-field else tab+(field to value)))))
    }
    @Test fun validLoggingChangesAreIndependentForOptionsAndActiveHandlers() {
        for(name in listOf(options,"human-handler")) for(level in 1..4) {
            val base=snapshot(name);val current=edit(base,name,"verbosity",JsonPrimitive(level))
            assertTrue(settingDependencyDifferences(plan(base),base,current).all { it.ownership=="NON_OWNED" && it.impact=="UNAFFECTED" })
        }
    }
    @Test fun malformedMissingAndUnknownLoggingFieldsRemainGuarded() {
        val base=snapshot()
        for(value in listOf(null,JsonNull,JsonPrimitive("4"),JsonPrimitive(0),JsonPrimitive(5),JsonPrimitive(3.5),JsonPrimitive(true))) {
            assertTrue(settingDependencyDifferences(plan(base),base,edit(base,options,"verbosity",value)).any { it.impact=="AFFECTED" })
        }
        assertTrue(settingDependencyDifferences(plan(base),base,edit(base,options,"future_verbosity",JsonPrimitive(4))).any { it.impact=="AFFECTED" })
    }
    @Test fun ownedLoggingAndRealToolFlagsRemainGuarded() {
        val base=snapshot();val approved=edit(base,options,"verbosity",JsonPrimitive(2));val current=edit(base,options,"verbosity",JsonPrimitive(4))
        assertTrue(settingDependencyDifferences(plan(base,approved),approved,current).any { it.ownership=="OWNED" && it.impact=="AFFECTED" })
        assertThrows(JobRejected::class.java) { approvedPhaseCandidate(base,approved,current) }
        assertTrue(settingDependencyDifferences(plan(base),base,edit(base,options,"chkbox_scanner",JsonPrimitive(false))).any { it.impact=="AFFECTED" })
    }
    @Test fun loggingIsPreservedAcrossApplyAndRestoreWithoutWeakeningReadback() {
        val base=snapshot();val approved=edit(base,options,"chkbox_scanner",JsonPrimitive(false));val current=edit(base,options,"verbosity",JsonPrimitive(4))
        val applied=approvedPhaseCandidate(base,approved,current)
        assertEquals(JsonPrimitive(4),applied.cph.getValue(options).jsonObject["verbosity"])
        assertEquals(JsonPrimitive(false),applied.cph.getValue(options).jsonObject["chkbox_scanner"])
        assertEquals(current,approvedPhaseCandidate(approved,base,applied))
        assertNotEquals(fingerprint(approved),fingerprint(applied))
    }
}
