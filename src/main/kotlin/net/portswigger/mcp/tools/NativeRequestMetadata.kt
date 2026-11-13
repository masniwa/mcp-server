package net.portswigger.mcp.tools

import burp.api.montoya.http.message.params.ParsedHttpParameter
import kotlinx.serialization.Serializable

@Serializable data class NativeParameterMetadata(val name:String,val type:String,val valueStart:Int,val valueEnd:Int,val valueSelectable:Boolean)

/** Uses the same native parser and byte offsets as the audit selector. No values or traffic. */
internal fun nativeParameterMetadata(parameters:List<ParsedHttpParameter>,requestLength:Int)=parameters.map {
    val range=it.valueOffsets();val start=range.startIndexInclusive();val end=range.endIndexExclusive()
    NativeParameterMetadata(it.name(),it.type().name,start,end,start>=0 && end>start && end<=requestLength)
}
