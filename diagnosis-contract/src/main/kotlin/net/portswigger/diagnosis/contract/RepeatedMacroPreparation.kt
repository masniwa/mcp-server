package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*

/** A literal revoked cookie belongs to once-only preparation, never a repeating native Macro. */
fun rejectFixedCookieRevocationMacro(macros:Collection<JsonObject>) {
    macros.forEach { macro ->
        (macro["items"] as? JsonArray).orEmpty().forEach item@ { value ->
            val item=value as? JsonObject ?: return@item
            if(item["use_request_cookies"]?.jsonPrimitive?.booleanOrNull!=false) return@item
            val request=item["request"]?.jsonPrimitive?.contentOrNull ?: return@item
            val response=item["response"]?.jsonPrimitive?.contentOrNull ?: return@item
            val revoked=response.substringBefore("\r\n\r\n").lineSequence().drop(1)
                .filter { it.substringBefore(':').equals("Set-Cookie",true) }
                .mapNotNull { header ->
                    val parts=header.substringAfter(':').split(';')
                    val first=parts.first().trim()
                    val at=first.indexOf('=')
                    if(at<=0) null else {
                        val name=first.substring(0,at).trim()
                        val cookieValue=first.substring(at+1).trim().removeSurrounding("\"")
                        val expired=parts.drop(1).any { attribute ->
                            attribute.substringBefore('=').trim().equals("Max-Age",true) &&
                                attribute.substringAfter('=',"").trim().toLongOrNull()?.let { it<=0 }==true
                        }
                        name.takeIf { cookieValue.isEmpty() || expired }
                    }
                }.toSet()
            if(revoked.isEmpty()) return@item
            request.substringBefore("\r\n\r\n").lineSequence().drop(1)
                .filter { it.substringBefore(':').equals("Cookie",true) }
                .flatMap { it.substringAfter(':').split(';').asSequence() }
                .forEach { cookie ->
                    val at=cookie.indexOf('=')
                    if(at>0) {
                        val name=cookie.substring(0,at).trim()
                        val literal=cookie.substring(at+1).trim().removeSurrounding("\"")
                        requireJob(name !in revoked || literal.isEmpty() ||
                            Regex("\\{\\{[^{}\\r\\n]+}}").containsMatchIn(literal),
                            "FIXED_COOKIE_REVOCATION_IN_REPEATED_MACRO")
                    }
                }
        }
    }
}
