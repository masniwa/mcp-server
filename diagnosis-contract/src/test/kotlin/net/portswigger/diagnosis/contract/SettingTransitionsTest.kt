package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SettingTransitionsTest {
    private val destination=Endpoint("http","fixture.invalid",8080,"/items")
    private val helper=Endpoint("http","helper.invalid",8080,"/login")
    private fun scopedRule(prefix:String,advanced:Boolean=false)=obj("""{"description":"human-rule","enabled":true,"url_scope":"custom","url_scope_advanced_mode":$advanced,"tools_scope":["Scanner","Extensions"],"include_in_scope":[{"enabled":true,"prefix":"$prefix"}],"actions":[{"macro_serial_number":1}]}""")
    private fun dependencySnapshot(rule:JsonObject?,macroName:String="source",nested:JsonArray=JsonArray(emptyList()))=snapshot("{}").copy(project=buildJsonObject {
        putJsonObject("sessions") {
            putJsonObject("session_handling_rules") { put("rules",JsonArray(listOfNotNull(rule))) }
            putJsonObject("macros") { putJsonArray("macros") {
                add(buildJsonObject { put("serial_number",1);put("description",macroName);put("items",nested) })
                add(obj("""{"serial_number":2,"description":"second"}"""))
                add(obj("""{"serial_number":3,"description":"third"}"""))
            } }
        }
    })
    private fun scopedPlan(baseline:BurpSnapshot,endpoints:List<Endpoint> = listOf(destination))=plan(baseline).copy(expandedEndpoints=endpoints)

    @Test fun foreignRuleAndItsExclusiveMacroChangesAndDeletionsAreUnaffected() {
        val baseline=dependencySnapshot(scopedRule("http://other.invalid:8080/first"))
        val current=dependencySnapshot(scopedRule("http://other.invalid:8080/second"),"human-edited")
        for(now in listOf(current,dependencySnapshot(null,"human-edited"),snapshot("{}"))) {
            val differences=settingDependencyDifferences(scopedPlan(baseline),baseline,now)
            assertTrue(differences.isNotEmpty())
            assertTrue(differences.all { it.impact=="UNAFFECTED" && it.ownership=="NON_OWNED" })
            assertEquals(now,approvedPhaseCandidate(baseline,baseline,now))
        }
    }
    @Test fun applicabilityBeforeAndAfterChangeAndHelperEndpointsRemainProtected() {
        val foreign=dependencySnapshot(scopedRule("http://other.invalid:8080/"))
        for(endpoint in listOf(destination,helper)) {
            val relevant=dependencySnapshot(scopedRule(endpoint.url()))
            val p=scopedPlan(foreign,listOf(destination,helper))
            for((before,after) in listOf(foreign to relevant,relevant to foreign,relevant to dependencySnapshot(null))) {
                assertTrue(settingDependencyDifferences(p,before,after).any { it.impact=="AFFECTED" })
            }
            val edited=dependencySnapshot(scopedRule(endpoint.url()),"edited-macro")
            assertTrue(settingDependencyDifferences(p,relevant,edited).any { it.path.contains("/macros/") && it.impact=="AFFECTED" })
        }
    }
    @Test fun advancedMalformedAndUnknownScopeRemainConservative() {
        val rules=listOf(scopedRule("http://other.invalid:8080/",true),scopedRule("invalid-prefix"),
            JsonObject(scopedRule("http://other.invalid:8080/")-"url_scope"))
        for(rule in rules) {
            val baseline=dependencySnapshot(rule)
            val current=dependencySnapshot(JsonObject(rule+("note" to JsonPrimitive("edited"))),"edited-macro")
            val differences=settingDependencyDifferences(scopedPlan(baseline),baseline,current)
            assertTrue(differences.any { it.path.contains("/session_handling_rules/") && it.impact=="AFFECTED" })
            assertTrue(differences.any { it.path.contains("/macros/") && it.impact=="AFFECTED" })
        }
    }
    @Test fun macroReferencesAreTraversedInBothSnapshotsWithCycleProtection() {
        val rule=scopedRule(destination.url())
        val baseline=dependencySnapshot(rule,nested=obj("""{"macro_serial_number":2}""").let { JsonArray(listOf(it)) })
        val current=dependencySnapshot(rule,nested=JsonArray(listOf(obj("""{"macro_serial_number":3}"""))))
        val differences=settingDependencyDifferences(scopedPlan(baseline),baseline,current)
        assertTrue(differences.any { it.path.contains("/macros/") && it.impact=="AFFECTED" })
        // Force each transitive source to change; both the old and new closure must remain protected.
        val bothChanged=current.copy(project=obj(current.project.toString().replace("second","second-edited").replace("third","third-edited")))
        val changed=settingDependencyDifferences(scopedPlan(baseline),baseline,bothChanged)
        for(id in listOf("serial:2","serial:3")) assertTrue(changed.any { it.path.contains(id) && it.impact=="AFFECTED" })
        val cyclic=dependencySnapshot(rule,nested=JsonArray(listOf(obj("""{"macro_serial_number":1}"""))))
        assertDoesNotThrow { settingDependencyDifferences(scopedPlan(cyclic),cyclic,bothChanged) }
    }
    @Test fun explicitPreparationsAndOwnedDefinitionsRemainProtectedOutsideScope() {
        val baseline=dependencySnapshot(scopedRule("http://other.invalid:8080/"))
        val rule=baseline.project.getValue("sessions").jsonObject.getValue("session_handling_rules").jsonObject.getValue("rules").jsonArray.single()
        val macro=baseline.project.getValue("sessions").jsonObject.getValue("macros").jsonObject.getValue("macros").jsonArray.first()
        val current=dependencySnapshot(JsonObject(rule.jsonObject+("note" to JsonPrimitive("edited"))),"edited-macro")
        val request=RequestPlan(destination,"GET /items HTTP/1.1\r\nHost: fixture.invalid:8080\r\n\r\n","fixture","source-hash")
        for(settings in listOf(SettingsPlan(rules=JsonArray(listOf(rule))),SettingsPlan(macros=JsonArray(listOf(macro))),
            SettingsPlan(macroPreparations=listOf(MacroPreparation(1,0,"fixture","source-hash"))),
            SettingsPlan(authenticationStates=AuthenticationStates(rules=mapOf("human-rule" to true))))) {
            val base=scopedPlan(baseline)
            val variant=ScanVariant("reflection","REFLECTION",request=request,settings=settings)
            val explicit=base.copy(proposal=base.proposal.copy(variants=listOf(variant)))
            val differences=settingDependencyDifferences(explicit,baseline,current)
            assertTrue(differences.any { it.path.contains("/macros/") && it.impact=="AFFECTED" })
            if(settings.rules.isNotEmpty() || settings.authenticationStates!=null)
                assertTrue(differences.any { it.path.contains("/session_handling_rules/") && it.impact=="AFFECTED" })
        }
        val base=scopedPlan(snapshot("{}"))
        val variant=ScanVariant("reflection","REFLECTION",request=request,settings=SettingsPlan())
        val owned=base.copy(variants=listOf(CompiledVariant(variant,baseline.project,baseline.cph,baseline.cphOrder,"settings")))
        assertTrue(settingDependencyDifferences(owned,baseline,current).any { it.ownership=="OWNED" && it.impact=="AFFECTED" })
    }

    @Test fun enabledRuleOrderIsASeparateDependencyWhileDisabledMovesArePreserved() {
        val baseline=snapshot("""{"sessions":{"session_handling_rules":{"rules":[{"description":"a","enabled":true},{"description":"off","enabled":false},{"description":"b","enabled":true}]}}}""")
        val rules=baseline.project.getValue("sessions").jsonObject.getValue("session_handling_rules").jsonObject.getValue("rules").jsonArray
        fun reordered(order:List<Int>)=baseline.copy(project=buildJsonObject {
            putJsonObject("sessions") { putJsonObject("session_handling_rules") { put("rules",JsonArray(order.map { rules[it] })) } }
        })
        val swapped=reordered(listOf(2,1,0))
        assertTrue(settingDependencyDifferences(plan(baseline),baseline,swapped).any { it.path.endsWith("/effective_order") && it.impact=="AFFECTED" })
        val disabledMoved=reordered(listOf(1,0,2))
        assertTrue(settingDependencyDifferences(plan(baseline),baseline,disabledMoved).isEmpty())
        assertEquals(disabledMoved,approvedPhaseCandidate(baseline,baseline,disabledMoved))
    }

    @Test fun simpleNativeQueryReadbackSupportsReverseTransitionButOtherRuleChangesRefuse() {
        val baseline=snapshot("{}")
        val approved=snapshot("""{"sessions":{"session_handling_rules":{"rules":[{"description":"job:fixture:scope","enabled":true,"url_scope_advanced_mode":false,"include_in_scope":[{"prefix":"https://fixture.invalid/api?mode=ReadItem"}],"exclude_from_scope":[]}]}}}""")
        val native=approved.copy(project=obj(approved.project.toString().replace("ReadItem","readitem")))
        val restored=approvedPhaseCandidate(approved,baseline,native)
        assertEquals(comparableNativeCollections(baseline.project),comparableNativeCollections(restored.project))
        assertEquals(native,approvedPhaseCandidate(baseline,approved,native))
        for(changed in listOf("/api" to "/API","fixture.invalid" to "other.invalid","\"enabled\":true" to "\"enabled\":false")) {
            val human=native.copy(project=obj(native.project.toString().replace(changed.first,changed.second)))
            assertThrows(JobRejected::class.java) { approvedPhaseCandidate(approved,baseline,human) }
        }
    }
    private fun obj(raw:String)=Json.parseToJsonElement(raw).jsonObject
    private fun snapshot(project:String)=BurpSnapshot("process",obj(project),obj("{}"),emptyList(),emptySet(),projectMarker="project")


    private fun plan(baseline:BurpSnapshot):CompiledPlan {
        val proposal=JobProposal(jobId="fixture",revision=1,objective="dependency comparison",targetPolicy=emptyList(),materials=emptyList(),
            session=SessionPlan(false,"OMIT","offline fixture","none"),variants=emptyList(),requiredCapabilities=emptySet(),cleanupPolicy="none")
        return CompiledPlan(proposal,"proposal-digest","plan-digest",baseline,emptyList(),emptyList())
    }
    @Test fun unusedMacroDeletionAndDisabledRuleEditsAreIndependentOfActiveReferences() {
        val baseline=snapshot("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"used"},{"serial_number":2,"description":"unused"}]},"session_handling_rules":{"rules":[{"description":"active","enabled":true,"actions":[{"macro_serial_number":1}]},{"description":"off","enabled":false}]}}}""")
        val current=snapshot("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"used"}]},"session_handling_rules":{"rules":[{"description":"active","enabled":true,"actions":[{"macro_serial_number":1}]},{"description":"off","enabled":false,"note":"human"}]}}}""")
        val differences=settingDependencyDifferences(plan(baseline),baseline,current)
        assertTrue(differences.isNotEmpty());assertTrue(differences.all { it.ownership=="NON_OWNED" && it.impact=="UNAFFECTED" })
        val changed=current.copy(project=obj(current.project.toString().replace("used","changed")))
        assertTrue(settingDependencyDifferences(plan(baseline),baseline,changed).any { it.impact=="AFFECTED" })
    }
    @Test fun newEnabledRuleAndChangedReferencedMacroRemainAffected() {
        val baseline=snapshot("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"source"}]},"session_handling_rules":{"rules":[{"description":"off","enabled":false}]}}}""")
        val current=snapshot("""{"sessions":{"macros":{"macros":[{"serial_number":1,"description":"source"}]},"session_handling_rules":{"rules":[{"description":"off","enabled":true}]}}}""")
        assertTrue(settingDependencyDifferences(plan(baseline),baseline,current).any { it.impact=="AFFECTED" })
        val unknown=current.copy(project=JsonObject(current.project+("network" to obj("""{"proxy":"changed"}"""))))
        assertTrue(settingDependencyDifferences(plan(baseline),baseline,unknown).any { it.impact=="UNKNOWN_IMPACT" })
    }
    @Test fun dynamicViewerUpdatesArePreservedAcrossForwardAndReversePhases() {
        val tab=obj("""{"enabled":false,"dynamic_checkbox":true,"extract_choice_index":0,"single_response":"initial"}""")
        val baseline=snapshot("{}").copy(cph=JsonObject(mapOf("source" to tab)),cphOrder=listOf("source"))
        val approved=baseline.copy(cph=JsonObject(mapOf("source" to JsonObject(tab+("enabled" to JsonPrimitive(true))))))
        val current=baseline.copy(cph=JsonObject(mapOf("source" to JsonObject(tab+("single_response" to JsonPrimitive("fresh"))))))
        val applied=approvedPhaseCandidate(baseline,approved,current)
        assertEquals(JsonPrimitive("fresh"),applied.cph.getValue("source").jsonObject["single_response"])
        assertEquals(JsonPrimitive(true),applied.cph.getValue("source").jsonObject["enabled"])
        val restored=approvedPhaseCandidate(approved,baseline,applied)
        assertEquals(JsonPrimitive(false),restored.cph.getValue("source").jsonObject["enabled"])
        assertEquals(JsonPrimitive("fresh"),restored.cph.getValue("source").jsonObject["single_response"])
    }
    @Test fun forwardPhasePreservesNonOwnedChangesAndDeletions() {
        val baseline=snapshot("""{"owned":false,"human":1,"removed":true}""")
        val approved=snapshot("""{"owned":true,"human":1,"removed":true}""")
        val current=snapshot("""{"owned":false,"human":2,"added":3}""")
        assertEquals(obj("""{"owned":true,"human":2,"added":3}"""),approvedPhaseCandidate(baseline,approved,current).project)
        assertEquals(current,approvedPhaseCandidate(baseline,baseline,current))
    }
    @Test fun ownedConflictRefusesBeforeApplyingAnything() {
        val baseline=snapshot("""{"owned":0}""")
        val approved=snapshot("""{"owned":1}""")
        val current=snapshot("""{"owned":2}""")
        assertEquals("OWNED_SETTING_CHANGED_BEFORE_APPLY",assertThrows(JobRejected::class.java) {
            approvedPhaseCandidate(baseline,approved,current)
        }.code)
    }
    @Test fun forwardPhaseIsIdempotentAndDoesNotInferProjectIdentity() {
        val baseline=snapshot("""{"owned":false}""")
        val approved=snapshot("""{"owned":true}""")
        assertEquals(approved,approvedPhaseCandidate(baseline,approved,approved))
        assertThrows(JobRejected::class.java) { approvedPhaseCandidate(baseline,approved,approved.copy(projectMarker="other")) }
        assertThrows(JobRejected::class.java) { approvedPhaseCandidate(baseline,approved,approved.copy(instanceId="other-process")) }
    }
}
