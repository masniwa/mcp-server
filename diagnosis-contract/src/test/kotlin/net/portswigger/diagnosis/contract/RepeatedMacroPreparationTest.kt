package net.portswigger.diagnosis.contract

import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RepeatedMacroPreparationTest {
    private fun item(requestCookie:String="OwnedKey=opaque-owned-value",setCookie:String="OwnedKey=; Path=/; Max-Age=0",
        useRequestCookies:Boolean=false,path:String="/session/end"):JsonObject = buildJsonObject {
        put("use_request_cookies",useRequestCookies)
        put("request","POST $path HTTP/1.1\r\nHost: other.invalid:8193\r\nCookie: $requestCookie\r\nContent-Length: 0\r\n\r\n")
        put("response","HTTP/1.1 204 No Content\r\nSet-Cookie: $setCookie\r\n\r\n")
    }
    private fun check(vararg items:JsonObject)=rejectFixedCookieRevocationMacro(listOf(buildJsonObject {
        put("items",JsonArray(items.toList()))
    }))

    @Test fun `literal owned cookie revoked by observed response cannot repeat in a Macro`() {
        val error=assertThrows(JobRejected::class.java) { check(item()) }
        assertEquals("FIXED_COOKIE_REVOCATION_IN_REPEATED_MACRO",error.code)
    }
    @Test fun `names destinations and revocation counts are generic`() {
        listOf("c9","SESSION_OTHER","customToken").forEach { name ->
            assertThrows(JobRejected::class.java) { check(item("$name=one-fixed-owned-key","$name=; Secure",path="/accounts/retire")) }
        }
        assertThrows(JobRejected::class.java) { check(item("other=x; c9=one-fixed-owned-key","c9=gone; max-age=-3")) }
    }
    @Test fun `cookie jar and dynamic placeholders preserve current-session cleanup`() {
        check(item(useRequestCookies=true))
        check(item("OwnedKey={{CURRENT_OWNED_COOKIE}}"))
        check(item("OwnedKey=prefix-{{CURRENT_OWNED_COOKIE}}"))
    }
    @Test fun `nonrevoking responses and distinct cookies remain valid`() {
        check(item(setCookie="OwnedKey=new-owned-value; Max-Age=600"))
        check(item(setCookie="DifferentKey=; Max-Age=0"))
        check(item("OwnedKey="))
        check(item("OwnedKey=\"\""))
        check(item("ownedkey=value")) // Cookie names are case sensitive.
    }
    @Test fun `header case multiple fields and quoted empty revocation are covered`() {
        val first=item("routing=value; OwnedKey=owned; token=x",setCookie="UnrelatedKey=value")
        val varied=JsonObject(first+("request" to JsonPrimitive(first.getValue("request").jsonPrimitive.content.replace("Cookie:","cOoKiE:")))+
            ("response" to JsonPrimitive("HTTP/1.1 200 OK\r\nsEt-CoOkIe: OtherKey=ok\r\nSet-Cookie: OwnedKey=\"\"; HttpOnly\r\n\r\n")))
        assertThrows(JobRejected::class.java) { check(varied) }
    }
    @Test fun `body text cannot masquerade as response or request cookies`() {
        val original=item(setCookie="UnrelatedKey=ok")
        val body=JsonObject(original+("response" to JsonPrimitive("HTTP/1.1 200 OK\r\n\r\nSet-Cookie: OwnedKey=; Max-Age=0")))
        check(body)
    }
}
