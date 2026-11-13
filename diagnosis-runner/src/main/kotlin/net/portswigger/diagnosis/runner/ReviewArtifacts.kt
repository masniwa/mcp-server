package net.portswigger.diagnosis.runner

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** Human-readable immutable copies supplement the protected SQL records; approval is still issued by the UI. */
class ReviewArtifacts(private val directory:Path) {
    fun write(value:JsonElement,label:String):Path {
        val root=directory.resolve("reviews");Files.createDirectories(root)
        val file=root.resolve("${fingerprint(value)}.$label.json")
        val bytes=canonical(value).toByteArray(Charsets.UTF_8)
        if(Files.exists(file)) requireJob(Files.readAllBytes(file).contentEquals(bytes),"REVIEW_ARTIFACT_CHANGED")
        else Files.write(file,bytes,StandardOpenOption.CREATE_NEW)
        return file
    }
}

/** Preserve native structure for review while replacing raw credential-bearing material with explicit digests. */
fun reviewProjection(value:JsonElement,key:String=""):JsonElement {
    val protected=setOf("password","certificate_password","hashed_key","request","response","single_request","single_response",
        "preset_value","original_value","static_expression","pages","loggerpages","bindings")
    if(key.lowercase() in protected && (value is JsonPrimitive || key.lowercase() in setOf("pages","loggerpages","bindings")))
        return buildJsonObject { put("protectedValueSha256",fingerprint(value));put("viewOriginal","protected local review file") }
    return when(value) {
        is JsonObject -> JsonObject(value.mapValues { (k,v) -> reviewProjection(v,k) })
        is JsonArray -> JsonArray(value.map { reviewProjection(it,key) })
        else -> value
    }
}
