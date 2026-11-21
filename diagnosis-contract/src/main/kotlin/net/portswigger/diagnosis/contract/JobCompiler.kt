package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** Pure compiler: no sockets, Burp, filesystem or AI inference. Native JSON is preserved losslessly. */
class JobCompiler {
    fun compile(job:JobProposal,baseline:BurpSnapshot):CompiledPlan = try {
        val initial=compileValidated(job,baseline)
        if(job.authenticationRetention==null) initial else {
            val retained=authenticationRestoration(initial)
            // Retained definitions are idle/disabled. Compile each variant's approved enabled
            // states against them, including inherited dependencies and input preservation.
            val executable=compileValidated(withoutRetainedDefinitions(job,retained,initial.variants),retained,
                initial.variants.map { nativeRules(it.project) })
            val variants=executable.variants.mapIndexed { index,v -> v.copy(variant=job.variants[index]) }
            val seed=buildJsonObject {
                put("proposal",initial.proposalDigest);put("baseline",fingerprint(baseline))
                put("variants",jobJson.encodeToJsonElement(variants));put("restorationBaseline",fingerprint(retained))
            }
            CompiledPlan(job,initial.proposalDigest,fingerprint(seed),baseline,variants,executable.expandedEndpoints,retained)
        }
    }
    catch(e:JobRejected) { throw e }
    catch(e:Exception) { throw JobRejected("INVALID_NATIVE_SETTINGS") }
    private fun nativeRules(project:JsonObject):List<JsonElement> =
        (project["project_options"]?.jsonObject ?: project)["sessions"]?.jsonObject
            ?.get("session_handling_rules")?.jsonObject?.get("rules")?.jsonArray.orEmpty()
    private fun compileValidated(job: JobProposal, baseline: BurpSnapshot,
        originalRuleOrder:List<List<JsonElement>>? = null): CompiledPlan {
        requireJob(job.schemaVersion == 1 && job.jobId.matches(Regex("[A-Za-z0-9_-]{1,80}")) && job.revision > 0, "INVALID_JOB_VERSION")
        requireJob(job.objective.isNotBlank() && job.cleanupPolicy.isNotBlank(), "MISSING_PURPOSE_OR_CLEANUP")
        requireJob(job.targetPolicy.isNotEmpty() && job.validationMaxAgeSeconds in 1..86400, "INVALID_POLICY")
        requireJob(job.executionApprovalMaxAgeSeconds in 1..86400, "INVALID_EXECUTION_APPROVAL_DURATION")
        job.targetPolicy.forEach { it.endpoint.validate() }
        requireJob(job.session.decisionReason.isNotBlank() && job.session.accountRef.isNotBlank() &&
            job.session.validationDecision in setOf("USE", "OMIT"), "SESSION_DECISION_REQUIRED")
        requireJob(job.requiredCapabilities.containsAll(setOf("SCANNER_WORKFLOW", "EXCLUSIVE_CONTEXT")) &&
            baseline.capabilities.containsAll(job.requiredCapabilities), "UNSUPPORTED_CAPABILITY")
        requireJob(job.dynamicBindings.isEmpty() || "DYNAMIC_WORKFLOW_VERIFIED" in job.requiredCapabilities, "DYNAMIC_CAPABILITY_REQUIRED")
        requireJob(job.materials.map { it.id }.distinct().size == job.materials.size, "DUPLICATE_MATERIAL")
        val materials = job.materials.associateBy { it.id }
        if(job.session.authenticationRequired && job.session.validationDecision=="USE") {
            val probe=materials[job.session.validationSourceId] ?: throw JobRejected("SESSION_VALIDATION_SOURCE_REQUIRED")
            requireJob(probe.request.startsWith("GET ") || probe.request.startsWith("HEAD "),"READ_ONLY_SESSION_PROBE_REQUIRED")
        }
        val endpoints = linkedSetOf<Endpoint>()
        fun allowed(e: Endpoint) { e.validate(); requireJob(job.targetPolicy.any { it.allows(e) }, "OUT_OF_SCOPE"); endpoints.add(e) }
        job.materials.forEach {
            requireJob(digest(it.request) == it.requestSha256 && digest(it.response) == it.responseSha256, "MATERIAL_CHANGED")
            checkRequest(it.endpoint, it.request); allowed(it.endpoint)
        }
        val seen = mutableSetOf<String>()
        job.dynamicBindings.forEach { b ->
            requireJob(b.id !in seen && b.dependsOn.all { it in seen }, "BINDING_ORDER_OR_CYCLE")
            requireJob(listOf(b.source,b.destination,b.extraction,b.insertion,b.timing,b.failurePolicy).all { it.isNotBlank() }, "INCOMPLETE_BINDING")
            seen.add(b.id)
        }
        requireJob(job.variants.isNotEmpty() && job.variants.map { it.id }.distinct().size == job.variants.size, "INVALID_VARIANTS")
        requireJob(job.variants.count { it.kind == "REFLECTION" } == 1, "REFLECTION_REQUIRED")
        InputCoverage.validateRequestedScope(job)
        requireJob(job.storedVerificationSourceIds.distinct().size == job.storedVerificationSourceIds.size &&
            job.storedVerificationSourceIds.all { it in materials } &&
            job.variants.filter { it.kind == "STORED" }.mapNotNull { it.verificationSourceId }.sorted() == job.storedVerificationSourceIds.sorted(), "STORED_COVERAGE_MISMATCH")
        val compiled = job.variants.mapIndexed { variantIndex,v ->
            requireJob(v.kind in setOf("REFLECTION", "STORED") && v.id.matches(Regex("[A-Za-z0-9_-]{1,80}")), "INVALID_VARIANT")
            requireJob(v.requiredBranches.isNotEmpty() && v.requiredBranches.distinct().size == v.requiredBranches.size, "INVALID_BRANCHES")
            val source = materials[v.request.sourceId] ?: throw JobRejected("SOURCE_NOT_OBSERVED")
            requireJob(v.request.sourceRequestSha256 == source.requestSha256, "SOURCE_CHANGED")
            checkRequest(v.request.endpoint, v.request.request); allowed(v.request.endpoint)
            requireJob(v.branchSetup.keys.all { it in v.requiredBranches } && v.requiredBranches.all { it=="normal" || it in v.branchSetup },"BRANCH_SETUP_REQUIRED")
            v.branchSetup.values.flatten().forEach { setup ->
                requireJob(materials[setup.sourceId]?.requestSha256==setup.sourceRequestSha256,"BRANCH_SOURCE_NOT_OBSERVED")
                checkRequest(setup.endpoint,setup.request);allowed(setup.endpoint)
                requireJob(setup.startOptions.isEmpty(),"BRANCH_SCAN_OPTIONS_FORBIDDEN")
            }
            v.preparationOnce.forEach { setup ->
                requireJob(materials[setup.sourceId]?.requestSha256==setup.sourceRequestSha256,"ONCE_PREPARATION_SOURCE_NOT_OBSERVED")
                checkRequest(setup.endpoint,setup.request);allowed(setup.endpoint)
                requireJob(setup.startOptions.isEmpty(),"ONCE_PREPARATION_SCAN_OPTIONS_FORBIDDEN")
            }
            InputCoverage.validateDeclarations(v.request.startOptions,v.inputExclusions)
            v.request.startOptions["payloadProfile"]?.jsonObject?.let { profile ->
                listOf("workbookPath","catalogPath").forEach { key -> profile[key]?.jsonPrimitive?.contentOrNull?.let {
                    requireJob(it in job.inputDigests,"PAYLOAD_SNAPSHOT_REQUIRED")
                } }
            }
            requireJob(v.request.startOptions.keys.all { it in setOf("insertionPointParameters", "payloadProfile", "etaProfile", "workload") }, "UNSUPPORTED_START_OPTION")
            val s = v.settings
            requireJob(s.macroPreparations.map { it.macroSerialNumber to it.itemIndex }.distinct().size==s.macroPreparations.size,"DUPLICATE_MACRO_PREPARATION")
            val ns = "job:${job.jobId}:"
            val projectRoot = baseline.project["project_options"]?.jsonObject ?: baseline.project
            val sessions = projectRoot["sessions"]?.jsonObject ?: JsonObject(emptyMap())
            val existingMacros = sessions["macros"]?.jsonObject?.get("macros")?.jsonArray ?: JsonArray(emptyList())
            val originalRules = sessions["session_handling_rules"]?.jsonObject?.get("rules")?.jsonArray ?: JsonArray(emptyList())
            val ruleStates=s.authenticationStates?.rules.orEmpty()
            requireJob(ruleStates.keys.all { name -> originalRules.count { it.jsonObject["description"]==JsonPrimitive(name) }==1 },
                "AUTHENTICATION_RULE_STATE_REFERENCE_REQUIRED")
            val existingRules=JsonArray(originalRules.map { value ->
                val rule=value.jsonObject;val name=rule["description"]?.jsonPrimitive?.content
                if(name in ruleStates) {
                    requireJob(rule["actions"]?.jsonArray?.any { it.jsonObject["type"]==JsonPrimitive("validate_session") }==true,
                        "AUTHENTICATION_RULE_VALIDATION_REQUIRED")
                    JsonObject(rule+("enabled" to JsonPrimitive(ruleStates.getValue(name!!))))
                } else value
            })
            s.macroPreparations.forEach { preparation ->
                val macro=(existingMacros+s.macros).firstOrNull { it.jsonObject["serial_number"]?.jsonPrimitive?.longOrNull==preparation.macroSerialNumber }?.jsonObject
                val items=macro?.get("items")?.jsonArray
                requireJob(items!=null && preparation.itemIndex in items.indices,"MACRO_PREPARATION_REFERENCE_REQUIRED")
                val item=items!![preparation.itemIndex].jsonObject
                validatePreparation(preparation,materials,item["request"]!!.jsonPrimitive.content,item["response"]!!.jsonPrimitive.content,endpoint(item["url"]!!.jsonPrimitive.content))
            }
            val ruleIds=s.rules.mapNotNull { it.jsonObject["serial_number"] }
            requireJob(ruleIds.distinct().size==ruleIds.size && ruleIds.none { id -> existingRules.any { it.jsonObject["serial_number"]==id } },"RULE_ID_COLLISION")
            val oldSerials = existingMacros.map { it.jsonObject["serial_number"] }.toSet()
            val serials = s.macros.map { it.jsonObject["serial_number"] }
            requireJob(serials.none { it == null || it.jsonPrimitive.isString || (it.jsonPrimitive.longOrNull ?: 0)<=0 || it in oldSerials } && serials.distinct().size == serials.size, "MACRO_ID_COLLISION")
            s.macros.forEach { macro ->
                val m = macro.jsonObject
                requireJob(m["description"]?.jsonPrimitive?.content?.startsWith(ns) == true, "MACRO_OWNERSHIP_REQUIRED")
                val items = m["items"]?.jsonArray ?: throw JobRejected("MACRO_ITEMS_REQUIRED")
                requireJob(items.isNotEmpty(), "EMPTY_MACRO")
                items.forEachIndexed { itemIndex,item ->
                    val i = item.jsonObject
                    val raw = i["request"]?.jsonPrimitive?.content ?: throw JobRejected("MACRO_REQUEST_REQUIRED")
                    val response = i["response"]?.jsonPrimitive?.content ?: throw JobRejected("MACRO_RESPONSE_REQUIRED")
                    val e = endpoint(i["url"]!!.jsonPrimitive.content); allowed(e); checkRequest(e, raw)
                    val preparation=s.macroPreparations.firstOrNull { it.macroSerialNumber==m["serial_number"]!!.jsonPrimitive.long && it.itemIndex==itemIndex }
                    if(preparation==null) requireJob(job.materials.any { it.request == raw && it.response == response && it.endpoint == e }, "MACRO_NOT_OBSERVED")
                    else validatePreparation(preparation,materials,raw,response,e)
                    requireJob(i.keys.containsAll(setOf("accept_response_cookies","custom_parameters","method","request","request_parameters","response","status_code","url","use_request_cookies")),"MACRO_NATIVE_FIELDS_REQUIRED")
                    requireJob(i["accept_response_cookies"]?.jsonPrimitive?.booleanOrNull==true && i["use_request_cookies"]?.jsonPrimitive?.booleanOrNull!=null &&
                        i["custom_parameters"] is JsonArray && i["request_parameters"] is JsonArray &&
                        i["method"]?.jsonPrimitive?.content==raw.substringBefore(' ') &&
                        i["status_code"]?.jsonPrimitive?.intOrNull==response.substringBefore("\r\n").split(' ').getOrNull(1)?.toIntOrNull(),"INVALID_MACRO_NATIVE_FIELDS")
                    validateNativeMacroParameters(m["description"]!!.jsonPrimitive.content,itemIndex,raw,i["request_parameters"]!!.jsonArray)
                }
            }
            val allSerials = oldSerials + serials
            fun inspectReferences(e: JsonElement) {
                nativeMacroReferences(e).forEach { requireJob(it in allSerials,"MISSING_MACRO_REFERENCE") }
            }
            s.rules.forEach { rule ->
                val r = rule.jsonObject
                requireJob(r["description"]?.jsonPrimitive?.content?.startsWith(ns) == true, "RULE_OWNERSHIP_REQUIRED")
                inspectReferences(r)
                requireJob(r.keys.containsAll(setOf("actions","description","enabled","exclude_from_scope","include_in_scope","named_params","restrict_scope_to_named_params","tools_scope","url_scope","url_scope_advanced_mode")),"RULE_NATIVE_FIELDS_REQUIRED")
                requireJob(r["enabled"]?.jsonPrimitive?.booleanOrNull!=null && r["exclude_from_scope"] is JsonArray && r["named_params"] is JsonArray &&
                    r["restrict_scope_to_named_params"]?.jsonPrimitive?.booleanOrNull!=null && r["tools_scope"] is JsonArray &&
                    r["url_scope"]?.jsonPrimitive?.content=="custom" && r["url_scope_advanced_mode"]?.jsonPrimitive?.booleanOrNull==false,"INVALID_RULE_NATIVE_FIELDS")
                val actions = r["actions"]?.jsonArray ?: throw JobRejected("RULE_ACTIONS_REQUIRED")
                requireJob(actions.all { it.jsonObject["type"]?.jsonPrimitive?.content in setOf("run_macro","run_post_request_macro","validate_session","invoke_extension") },"UNSUPPORTED_RULE_ACTION")
                r["include_in_scope"]?.jsonArray?.forEach { allowed(endpoint(it.jsonObject["prefix"]!!.jsonPrimitive.content)) }
            }
            val mergedRules=(existingRules+s.rules).toMutableList()
            val orderedRules=originalRuleOrder?.get(variantIndex)?.map { original ->
                val at=mergedRules.indexOf(original)
                requireJob(at>=0,"RETAINED_RULE_ORDER_MISMATCH")
                mergedRules.removeAt(at)
            }?.let { ordered ->
                requireJob(mergedRules.all { it.jsonObject["enabled"]==JsonPrimitive(false) },"RETAINED_EXTRA_RULE_ENABLED")
                ordered+mergedRules
            } ?: mergedRules
            val applicableRules=orderedRules.map { it.jsonObject }.filter { InputCoverage.ruleMayApply(it,v.request.endpoint) }
            val actions=applicableRules.flatMap { rule -> rule["actions"]?.jsonArray.orEmpty() }.map { it.jsonObject }
                .filter { it["enabled"]?.jsonPrimitive?.booleanOrNull!=false }
            applicableRules.forEach(::inspectReferences)
            val relevantMacros=mutableSetOf<JsonObject>()
            fun inspectAction(element:JsonElement) {
                nativeMacroReferences(element).forEach { serial ->
                    val macro=(existingMacros+s.macros).firstOrNull { it.jsonObject["serial_number"]==serial }?.jsonObject
                        ?: throw JobRejected("MISSING_MACRO_REFERENCE")
                    relevantMacros.add(macro)
                    macro["items"]?.jsonArray?.forEach { item ->
                        val i=item.jsonObject;val e=endpoint(i["url"]!!.jsonPrimitive.content)
                        allowed(e);checkRequest(e,i["request"]!!.jsonPrimitive.content)
                    }
                }
            }
            actions.forEach(::inspectAction)
            InputCoverage.validateMacroPreservation(v.request.startOptions,actions)
            rejectFixedCookieRevocationMacro(relevantMacros)
            val posts=actions.filter { it["type"]?.jsonPrimitive?.content=="run_post_request_macro" }
            if(v.kind=="REFLECTION") requireJob(posts.all { it["pass_back"]?.jsonPrimitive?.content=="current_response" },"REFLECTION_RESPONSE_CHANGED")
            if(v.kind=="STORED") {
                requireJob(posts.size==1 && posts.single()["pass_back"]?.jsonPrimitive?.content=="final_response" && actions.lastOrNull()==posts.single(),"STORED_RESPONSE_REQUIRED")
                val macro=(existingMacros+s.macros).firstOrNull { it.jsonObject["serial_number"]==posts.single()["macro_serial_number"] }?.jsonObject
                val final=macro?.get("items")?.jsonArray?.lastOrNull()?.jsonObject
                val observed=materials[v.verificationSourceId]
                val prepared=s.macroPreparations.any { it.macroSerialNumber==posts.single()["macro_serial_number"]?.jsonPrimitive?.longOrNull &&
                    it.itemIndex==macro?.get("items")?.jsonArray?.lastIndex && it.sourceId==v.verificationSourceId }
                requireJob(observed!=null && (final?.get("request")?.jsonPrimitive?.content==observed.request || prepared) &&
                    final?.get("response")?.jsonPrimitive?.content==observed.response,"STORED_MACRO_DESTINATION_MISMATCH")
            }
            if(job.session.authenticationRequired && job.session.validationDecision=="USE") {
                val observed=materials.getValue(job.session.validationSourceId!!)
                requireJob(actions.any { action ->
                    if(action["type"]?.jsonPrimitive?.content!="validate_session") false else
                        when(action["validation_action"]?.jsonPrimitive?.content) {
                            "run_macro" -> (existingMacros+s.macros).firstOrNull { it.jsonObject["serial_number"]==action["macro_serial_number"] }
                                ?.jsonObject?.get("items")?.jsonArray?.lastOrNull()?.jsonObject?.get("request")?.jsonPrimitive?.content==observed.request
                            "issue_current_request" -> observed.endpoint==v.request.endpoint && v.request.request.substringBefore(' ') in setOf("GET","HEAD")
                            else -> false
                        }
                },"SESSION_VALIDATION_ACTION_REQUIRED")
            }
            requireJob(s.cphOrder.distinct().size == s.cphOrder.size && s.cphOrder.containsAll(s.cph.keys) &&
                s.cphOrder.all { it in s.cph || it in baseline.cph }, "CPH_ORDER_REQUIRED")
            val cphStates=s.authenticationStates?.cph.orEmpty()
            requireJob(cphStates.keys.all { it in baseline.cph && it!=digest("options") && it !in s.cph },
                "AUTHENTICATION_CPH_STATE_REFERENCE_REQUIRED")
            val cph=applyAuthenticationToolScope(s.authenticationStates,JsonObject((baseline.cph+s.cph).mapValues { (name,value) ->
                if(name in cphStates) JsonObject(value.jsonObject+("enabled" to JsonPrimitive(cphStates.getValue(name)))) else value
            }))
            val requestedOrder=s.cphOrder+baseline.cphOrder.filter { it !in s.cphOrder }
            // Native export always places shared Options last; only actual handler tabs have processing order.
            val optionsKey=digest("options")
            val order=requestedOrder.filter { it!=optionsKey }+listOfNotNull(optionsKey.takeIf { it in cph })
            val nativeDynamic=s.macroPreparations.any { it.cphTrigger!=null || it.substitutions.any { s -> s.after.contains("{{") } } ||
                cph.values.any { it.jsonObject["enabled"]?.jsonPrimitive?.booleanOrNull!=false && it.jsonObject["dynamic_checkbox"]?.jsonPrimitive?.booleanOrNull==true } ||
                relevantMacros.any { macro -> macro["items"]?.jsonArray?.any { item ->
                    item.jsonObject["custom_parameters"]?.jsonArray?.isNotEmpty()==true || item.jsonObject["request_parameters"]?.jsonArray?.any {
                        it.jsonObject["parameter_handling"]?.jsonPrimitive?.content=="derive_from_prior_response"
                    }==true
                }==true }
            requireJob(!nativeDynamic || "DYNAMIC_WORKFLOW_VERIFIED" in job.requiredCapabilities,"DYNAMIC_CAPABILITY_REQUIRED")
            val requiredCph=cphDependencyClosure(cph,activeCphNames(cph)+s.cph.keys.filter { it!=optionsKey })
            order.forEachIndexed { index, name ->
                requireJob(name !in s.cph || name.startsWith(ns) || name == digest("options"), "CPH_OWNERSHIP_REQUIRED")
                if(name in s.cph) validateNativeCphTab(name,cph.getValue(name))
                val t = cph.getValue(name).jsonObject
                val known=if(name==digest("options")) setOf("verbosity","chkbox_proxy","chkbox_target","chkbox_spider","chkbox_repeater","chkbox_sequencer","chkbox_intruder","chkbox_scanner","chkbox_extender") else
                    setOf("enabled","modify_scope_choice_index","modify_type_choice_index","modify_expression","auto_encode","enable_forwarder","forwarder","match_expression","indices_choice_index","extract_choice_index","match_indices","static_expression","dynamic_checkbox","single_expression","issuer","single_request","single_response","macro_expression","cached_expression","cached_selection")
                requireJob(name !in s.cph || t.keys.all { it in known },"UNSUPPORTED_CPH_FIELD")
                if(name in requiredCph && t["dynamic_checkbox"]?.jsonPrimitive?.booleanOrNull==true && t["extract_choice_index"]?.jsonPrimitive?.intOrNull==2) t["cached_selection"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }?.let { ref ->
                    requireJob(ref in order.take(index), "CPH_CACHE_REFERENCE_ORDER")
                }
                val active=t["enabled"]?.jsonPrimitive?.booleanOrNull!=false
                val singleActive=active && t["dynamic_checkbox"]?.jsonPrimitive?.booleanOrNull==true && t["extract_choice_index"]?.jsonPrimitive?.intOrNull==0
                if(active && t["dynamic_checkbox"]?.jsonPrimitive?.booleanOrNull==true) {
                    requireJob(t["extract_choice_index"]?.jsonPrimitive?.intOrNull in 0..2,"CPH_EXTRACTION_MODE_REQUIRED")
                    if(singleActive) requireJob(t["issuer"] is JsonArray && t["single_request"]?.jsonPrimitive?.contentOrNull?.isNotBlank()==true,"CPH_SOURCE_REQUEST_REQUIRED")
                    if(t["extract_choice_index"]?.jsonPrimitive?.intOrNull==2) requireJob(t["cached_selection"]?.jsonPrimitive?.contentOrNull?.isNotBlank()==true,"CPH_CACHE_REFERENCE_REQUIRED")
                }
                listOf("issuer", "forwarder").forEach { key -> t[key]?.jsonArray?.let { socket ->
                    if (key == "issuer" && singleActive || key=="forwarder" && active && t["enable_forwarder"]?.jsonPrimitive?.booleanOrNull == true) {
                        requireJob(socket.size == 3, "CPH_SOCKET_REQUIRED")
                        val host = socket[1].jsonPrimitive.content
                        val port = socket[2].jsonPrimitive.int
                        val scheme = if (socket[0].jsonPrimitive.boolean) "https" else "http"
                        // Socket-level permit must cover at least the actual service. Requests below narrow paths.
                        requireJob(job.targetPolicy.any { it.endpoint.host.equals(host,true) && it.endpoint.port==port && it.endpoint.scheme==scheme }, "CPH_SOCKET_OUT_OF_SCOPE")
                    }
                } }
                t["single_request"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() && singleActive }?.let { raw ->
                    val socket = t["issuer"]!!.jsonArray
                    val path = raw.lineSequence().first().split(' ').getOrNull(1) ?: throw JobRejected("INVALID_CPH_REQUEST")
                    val e = Endpoint(if(socket[0].jsonPrimitive.boolean) "https" else "http",socket[1].jsonPrimitive.content,socket[2].jsonPrimitive.int,path)
                    allowed(e); checkRequest(e, raw)
                }
            }
            val newSessions = JsonObject(sessions + mapOf(
                "macros" to JsonObject((sessions["macros"]?.jsonObject ?: JsonObject(emptyMap())) + ("macros" to JsonArray(existingMacros + s.macros))),
                "session_handling_rules" to JsonObject((sessions["session_handling_rules"]?.jsonObject ?: JsonObject(emptyMap())) + ("rules" to JsonArray(orderedRules)))
            ))
            var newRoot = JsonObject(projectRoot + ("sessions" to newSessions))
            if(s.serialScannerRequests) {
                val pools=projectRoot["resource_pools"] as? JsonObject
                val pool=pools?.get("default_resource_pool") as? JsonObject
                requireJob(pool!=null && pool["concurrent_request_limit_enabled"]?.jsonPrimitive?.booleanOrNull!=null &&
                    (pool["concurrent_request_limit"]?.jsonPrimitive?.intOrNull ?: 0)>0,"RESOURCE_POOL_CONFIGURATION_REQUIRED")
                val serialPool=JsonObject(pool!!+mapOf("concurrent_request_limit_enabled" to JsonPrimitive(true),"concurrent_request_limit" to JsonPrimitive(1)))
                newRoot=JsonObject(newRoot+("resource_pools" to JsonObject(pools+("default_resource_pool" to serialPool))))
            }
            var project = if ("project_options" in baseline.project) JsonObject(baseline.project + ("project_options" to newRoot)) else newRoot
            s.targetScope?.let { scope ->
                requireJob(scope["advanced_mode"]?.jsonPrimitive?.booleanOrNull!=true,"UNSUPPORTED_NEW_ADVANCED_SCOPE")
                requireJob(scope["include"]?.jsonArray?.all { it.jsonObject["prefix"]!=null }!=false,"SCOPE_PREFIX_REQUIRED")
                scope["include"]?.jsonArray?.forEach { entry -> entry.jsonObject["prefix"]?.jsonPrimitive?.content?.let { allowed(endpoint(it)) } }
                val top = if ("target" in baseline.project) baseline.project else projectRoot
                val oldTarget=top["target"]?.jsonObject ?: JsonObject(emptyMap())
                val oldScope=oldTarget["scope"]?.jsonObject ?: JsonObject(emptyMap())
                requireJob(oldScope["advanced_mode"]?.jsonPrimitive?.booleanOrNull!=true,"ADVANCED_SCOPE_MUST_BE_PRESERVED")
                val mergedScope=JsonObject(oldScope+scope+listOf("include","exclude").associateWith { key ->
                    JsonArray(((oldScope[key] as? JsonArray).orEmpty()+(scope[key] as? JsonArray).orEmpty()).distinct())
                })
                val target = JsonObject(oldTarget + ("scope" to mergedScope))
                project = if ("target" in baseline.project) JsonObject(project + ("target" to target)) else
                    if ("project_options" in project) JsonObject(project + ("project_options" to JsonObject(newRoot + ("target" to target)))) else JsonObject(project + ("target" to target))
            }
            CompiledVariant(v, project, cph, order, settingsDigest(project,cph,order))
        }
        val proposalDigest = fingerprint(job)
        val seed = buildJsonObject { put("proposal", proposalDigest); put("baseline", fingerprint(baseline)); put("variants", jobJson.encodeToJsonElement(compiled)) }
        return CompiledPlan(job, proposalDigest, fingerprint(seed), baseline, compiled, endpoints.toList())
    }

    private fun validatePreparation(p:MacroPreparation,materials:Map<String,HttpMaterial>,request:String,response:String,destination:Endpoint) {
        val observed=materials[p.sourceId] ?: throw JobRejected("MACRO_PREPARATION_SOURCE_REQUIRED")
        requireJob(observed.requestSha256==p.sourceRequestSha256 && observed.response==response,"MACRO_PREPARATION_SOURCE_CHANGED")
        var prepared=observed.request
        p.substitutions.forEach { substitution ->
            val at=prepared.indexOf(substitution.before)
            requireJob(substitution.before.isNotEmpty() && at>=0 && prepared.indexOf(substitution.before,at+1)<0,"MACRO_PREPARATION_NOT_UNIQUE")
            prepared=prepared.replaceRange(at,at+substitution.before.length,substitution.after)
        }
        p.cphTrigger?.let { trigger ->
            requireJob(trigger.isNotBlank() && !trigger.contains(Regex("[\\r\\n]")) &&
                observed.request.substringBefore("\r\n\r\n").lineSequence().none { it.startsWith("X-cphtarget:",true) },"INVALID_CPH_TRIGGER_PREPARATION")
            val boundary=prepared.indexOf("\r\n\r\n")
            requireJob(boundary>=0,"HTTP_CRLF_REQUIRED")
            prepared=prepared.substring(0,boundary)+"\r\nX-cphtarget: $trigger"+prepared.substring(boundary)
        }
        requireJob(prepared==request && prepared.substringBefore(' ')==observed.request.substringBefore(' ') &&
            destination.host.equals(observed.endpoint.host,true) && destination.port==observed.endpoint.port && destination.scheme==observed.endpoint.scheme,
            "MACRO_PREPARATION_MISMATCH")
    }

    private fun checkRequest(e: Endpoint, raw: String) {
        requireJob(raw.contains("\r\n\r\n"), "HTTP_CRLF_REQUIRED")
        val first = raw.substringBefore("\r\n").split(' ')
        requireJob(first.size == 3 && first[0].matches(Regex("[A-Z]+")) && first[1] == e.path && first[2].startsWith("HTTP/"), "REQUEST_ENDPOINT_MISMATCH")
        val hosts=raw.substringBefore("\r\n\r\n").lineSequence().drop(1).filter { it.startsWith("Host:",true) }.toList()
        requireJob(hosts.size==1,"ONE_HOST_HEADER_REQUIRED")
        val host = hosts.firstOrNull()?.substringAfter(':')?.trim()
        requireJob(host != null && (host.equals(e.host,true) && e.port == (if(e.scheme=="https") 443 else 80) || host.equals("${e.host}:${e.port}",true)), "HOST_MISMATCH")
    }
}
