package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.nio.file.*

// Installation evidence and settings are bound to the same operator-selected runtime.
internal class InstallationProfile(private val path: Path) {
    @Synchronized fun register(evidence: JsonObject): JsonObject {
        val capability = evidence.getValue("capability").jsonPrimitive.content
        requireJob(capability in setOf("EXCLUSIVE_CONTEXT", "SCANNER_WORKFLOW", "DYNAMIC_WORKFLOW_VERIFIED"),
            "UNKNOWN_INSTALLATION_CAPABILITY")
        requireJob(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path.parent),
            "UNSAFE_RUNTIME_FILE")
        val original = Files.readString(path)
        val profile = jobJson.parseToJsonElement(original).jsonObject
        val mode = profile["authorizationMode"]?.jsonPrimitive?.content ?: InstalledRuntime.defaultAuthorizationMode()
        requireJob(mode == "REVIEW" && profile["schemaVersion"]?.jsonPrimitive?.intOrNull == 1,
            "INSTALLATION_REVIEW_REQUIRED")
        val capabilities = profile.getValue("verifiedCapabilities").jsonArray.map { it.jsonPrimitive.content }
        val proofs = profile["capabilityEvidence"]?.jsonObject.orEmpty()
        val updated = JsonObject(profile + mapOf(
            "verifiedCapabilities" to JsonArray((capabilities + capability).distinct().map(::JsonPrimitive)),
            "capabilityEvidence" to JsonObject(proofs + (capability to JsonPrimitive(fingerprint(evidence))))
        ))
        val temporary = Files.createTempFile(path.parent, ".setup-", ".tmp")
        try {
            Files.writeString(temporary, updated.toString())
            requireJob(Files.readString(path) == original, "INSTALLATION_PROFILE_CHANGED")
            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally {
            Files.deleteIfExists(temporary)
        }
        return JsonObject(evidence + ("registeredForNextLoad" to JsonPrimitive(true)))
    }
}