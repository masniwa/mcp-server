package net.portswigger.mcp.jobs

import java.nio.file.Path
import java.security.MessageDigest
import net.portswigger.diagnosis.contract.requireJob
import kotlinx.serialization.json.*

data class ManagedSettings(val enabled:Boolean, val workerToken:String?, val cphToken:String?, val directory:Path?,val capabilities:Set<String>,
    val inputRoots:List<Path> = emptyList(),val secretGenerationsFile:Path?=null,val profileFile:Path?=null,
    val quick:Boolean=false) {
    /** Non-secret STARTUP selection; do not expose this data class (it contains tokens). */
    fun connectionMetadata() = buildJsonObject {
        put("source",if(profileFile!=null) "file" else if(enabled) "environment" else "standalone")
        put("runtimeDirectory",profileFile?.parent?.toAbsolutePath()?.normalize()?.toString()?.let { JsonPrimitive(it) } ?: JsonNull)
        if(enabled) put("authorizationMode",if(quick) "QUICK" else "REVIEW")
    }
    fun authorized(header:String?):Boolean = enabled && workerToken!=null && header!=null &&
        MessageDigest.isEqual(header.toByteArray(),"Bearer $workerToken".toByteArray())
    companion object {
        fun forExtension(env:Map<String,String> = System.getenv(),root:Path?=InstalledRuntime.currentRoot()):ManagedSettings =
            if("BURP_DIAG_MANAGED" in env || root==null) environment(env) else InstalledRuntime.load(root)
        fun environment(env:Map<String,String> = System.getenv()):ManagedSettings {
            val enabled=env["BURP_DIAG_MANAGED"]=="1"
            if(!enabled) return ManagedSettings(false,null,null,null,emptySet())
            val token=env["BURP_DIAG_WORKER_TOKEN"];val cph=env["BURP_DIAG_CPH_TOKEN"]
            requireJob(token!=null && token.length>=32 && cph!=null && cph.length>=32 && token!=cph,"MANAGED_TOKENS_REQUIRED")
            val directory=env["BURP_DIAG_STORE"]?.let(Path::of)
            requireJob(directory!=null && directory.isAbsolute,"MANAGED_STORE_REQUIRED")
            // Capability assertions are operator launch configuration, not AI-supplied job data.
            val capabilities=env["BURP_DIAG_VERIFIED_CAPABILITIES"]?.split(',')?.filter { it.isNotBlank() }?.toSet() ?: emptySet()
            val mode=env["BURP_DIAG_AUTHORIZATION_MODE"] ?: InstalledRuntime.defaultAuthorizationMode()
            requireJob(mode in setOf("REVIEW","QUICK"),"INVALID_AUTHORIZATION_MODE")
            return ManagedSettings(true,token,cph,directory,capabilities,
                env["BURP_DIAG_INPUT_ROOTS"]?.split(java.io.File.pathSeparator)?.filter { it.isNotBlank() }?.map(Path::of).orEmpty(),
                env["BURP_DIAG_SECRET_GENERATIONS"]?.let(Path::of),quick=mode=="QUICK")
        }
    }
}
