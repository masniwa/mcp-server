package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RecoveryReplanTest {
    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    private val rule=obj("""{"description":"job:fixture:rule","enabled":true,"include_in_scope":[{"enabled":true,"prefix":"https://fixture.invalid/api?operation=ReadItem"}],"exclude_from_scope":[]}""")
    private fun fixture():CompiledPlan {
        val endpoint=Endpoint("https","fixture.invalid",443,"/api?operation=ReadItem")
        val variant=ScanVariant("reflection","REFLECTION",request=RequestPlan(endpoint,"observed request","source","observed hash"),
            settings=SettingsPlan(rules=JsonArray(listOf(rule))))
        val proposal=JobProposal(jobId="fixture",revision=1,objective="native candidate",targetPolicy=listOf(TargetPermit(endpoint)),materials=emptyList(),
            session=SessionPlan(false,"OMIT","offline fixture","none"),variants=listOf(variant),requiredCapabilities=emptySet(),cleanupPolicy="none")
        val baseline=BurpSnapshot("old-process",obj("{}"),obj("{}"),emptyList(),emptySet(),projectMarker="saved-project")
        return CompiledPlan(proposal,"old-proposal","old-plan",baseline,emptyList(),listOf(endpoint))
    }
    private fun observed(ruleValue:JsonObject)=fixture().baseline.copy(project=buildJsonObject {
        putJsonObject("sessions") { putJsonObject("session_handling_rules") { put("rules",JsonArray(listOf(ruleValue))) } }
    })
    @Test fun observedScopeBecomesExplicitNewRevisionWithoutChangingSourceOrOldDigest() {
        val plan=fixture();val old=fingerprint(plan)
        val native=obj(rule.toString().replace("ReadItem","readitem"))
        val candidate=observedRecoveryProposal(plan,observed(native),RecoveryReplanSelection(2,listOf("job:fixture:rule")))
        assertEquals(2,candidate.revision);assertEquals(native,candidate.variants.single().settings.rules.single())
        assertEquals(plan.proposal.variants.single().request,candidate.variants.single().request)
        assertEquals(plan.proposal.targetPolicy,candidate.targetPolicy);assertEquals(old,fingerprint(plan))
    }
    @Test fun changedHostPathActivationAndBroaderScopeAreRefused() {
        for(native in listOf(
            obj(rule.toString().replace("fixture.invalid","other.invalid")),
            obj(rule.toString().replace("/api?","/other?")),
            obj(rule.toString().replace("/api?operation=ReadItem","/")),
            JsonObject(rule+("enabled" to JsonPrimitive(false)))
        )) assertThrows(JobRejected::class.java) {
            observedRecoveryProposal(fixture(),observed(native),RecoveryReplanSelection(2,listOf("job:fixture:rule")))
        }
    }
    @Test fun missingRuleOldRevisionAndWrongProjectNeverProduceARecoveryCandidate() {
        val plan=fixture()
        assertThrows(JobRejected::class.java) { observedRecoveryProposal(plan,observed(rule),RecoveryReplanSelection(1)) }
        assertThrows(JobRejected::class.java) { observedRecoveryProposal(plan,observed(rule).copy(projectMarker="other"),RecoveryReplanSelection(2)) }
        assertThrows(JobRejected::class.java) { observedRecoveryProposal(plan,observed(rule),RecoveryReplanSelection(2,listOf("missing"))) }
    }
}