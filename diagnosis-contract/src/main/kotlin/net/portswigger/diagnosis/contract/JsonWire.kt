package net.portswigger.diagnosis.contract

/** Escape an already serialized JSON document without changing its decoded values.
 * ASCII wire text avoids dependence on receivers decoding a UTF-8 code point across chunks.
 * Never apply this to raw HTTP or ordinary non-JSON text. Surrogate pairs retain both code units.
 */
fun asciiJson(serialized:String):String {
    if(serialized.all { it.code<128 }) return serialized
    val hex="0123456789abcdef"
    return buildString(serialized.length) {
        for(c in serialized) {
            if(c.code<128) append(c) else {
                append("\\u")
                append(hex[(c.code ushr 12) and 15]);append(hex[(c.code ushr 8) and 15])
                append(hex[(c.code ushr 4) and 15]);append(hex[c.code and 15])
            }
        }
    }
}
