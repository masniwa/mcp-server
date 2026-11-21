package net.portswigger.mcp.security

import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Optional local CPH credentials. Legacy standalone installs need no profile. */
object LocalCphCredentials {
    @Volatile private var selectedRoot:Path?=null
    fun useInstallation(jar:Path) { selectedRoot=rootForJar(jar) }
    fun rootForJar(jar:Path):Path {
        val parent=jar.toAbsolutePath().normalize().parent
        return if(parent.fileName.toString()=="libs" && parent.parent?.fileName?.toString()=="build") parent.parent.parent else parent
    }
    fun currentRoot():Path?=selectedRoot ?: runCatching {
        val path=Path.of(LocalCphCredentials::class.java.protectionDomain.codeSource.location.toURI())
        if(Files.isRegularFile(path) && path.fileName.toString().endsWith(".jar")) rootForJar(path) else null
    }.getOrNull()
    fun authorization(host:String,port:Int,root:Path?=currentRoot()):String? {
        // Never load or forward the local credential for a user-supplied remote service.
        if(host !in setOf("127.0.0.1","localhost") || port!=17866 || root==null) return null
        return try {
            var directory=root.resolve("runtime")
            val connection=directory.resolve("cph-connection.json")
            if(Files.isRegularFile(connection,LinkOption.NOFOLLOW_LINKS)) {
                val path=Json.parseToJsonElement(Files.readString(connection)).jsonObject.getValue("runtimeDirectory").jsonPrimitive.content
                directory=directory.resolve(path).normalize()
            }
            val secrets=directory.resolve("operator-secrets.json")
            if(!Files.exists(secrets,LinkOption.NOFOLLOW_LINKS)) return null
            require(!Files.isSymbolicLink(directory) && Files.isRegularFile(secrets,LinkOption.NOFOLLOW_LINKS))
            val token=Json.parseToJsonElement(Files.readString(secrets)).jsonObject.getValue("cph").jsonPrimitive.content
            require(token.length>=32)
            "Bearer $token"
        } catch(e:Exception) { throw IllegalStateException("CPH_LOCAL_CREDENTIALS_INVALID") }
    }
}
