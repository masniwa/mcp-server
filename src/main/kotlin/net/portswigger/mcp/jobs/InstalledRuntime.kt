package net.portswigger.mcp.jobs

import kotlinx.serialization.json.*
import net.portswigger.diagnosis.contract.requireJob
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/** Operator configuration beside the installation; never resolve against cwd or temp. */
object InstalledRuntime {
    fun defaultAuthorizationMode():String = java.util.Properties().also { properties ->
        InstalledRuntime::class.java.getResourceAsStream("/diagnostic-profile.properties")?.use(properties::load)
    }.getProperty("authorizationMode","REVIEW").also { requireJob(it in setOf("REVIEW","QUICK"),"INVALID_AUTHORIZATION_MODE") }
    fun rootForJar(jar:Path):Path {
        val parent=jar.toAbsolutePath().normalize().parent
        return if(parent.fileName.toString()=="libs" && parent.parent?.fileName?.toString()=="build") parent.parent.parent else parent
    }
    fun currentRoot():Path? = runCatching {
        val path=Path.of(InstalledRuntime::class.java.protectionDomain.codeSource.location.toURI())
        if(Files.isRegularFile(path) && path.fileName.toString().endsWith(".jar")) rootForJar(path) else null
    }.getOrNull()
    private fun privateFile(file:Path) {
        val acl=Files.getFileAttributeView(file,AclFileAttributeView::class.java)
        if(acl!=null) acl.acl=listOf(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(Files.getOwner(file))
            .setPermissions(enumValues<AclEntryPermission>().toSet()).build())
        else Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"))
    }
    fun load(root:Path):ManagedSettings {
        val directory=root.toAbsolutePath().normalize().resolve("runtime")
        requireJob(!Files.isSymbolicLink(directory),"UNSAFE_RUNTIME_DIRECTORY")
        Files.createDirectories(directory)
        val settingsFile=directory.resolve("settings.json")
        if(!Files.exists(settingsFile,LinkOption.NOFOLLOW_LINKS)) {
            val defaults=buildJsonObject {
                put("schemaVersion",1);put("workerStore","worker-store");put("workerUrl","http://127.0.0.1:9876/diagnosis/worker")
                put("authorizationMode",defaultAuthorizationMode())
                put("inputRoots",buildJsonArray { add("jobs") });put("verifiedCapabilities",JsonArray(emptyList()))
            }
            Files.writeString(settingsFile,defaults.toString(),StandardOpenOption.CREATE_NEW)
        }
        val secretsFile=directory.resolve("operator-secrets.json")
        if(!Files.exists(secretsFile,LinkOption.NOFOLLOW_LINKS)) {
            val random=SecureRandom()
            fun secret()=ByteArray(48).also(random::nextBytes).joinToString("") { "%02x".format(it) }
            val secrets=buildJsonObject { put("worker",secret());put("cph",secret()) }
            try {
                // Protect the empty file before writing any credential bytes.
                Files.createFile(secretsFile);privateFile(secretsFile)
                Files.writeString(secretsFile,secrets.toString(),StandardOpenOption.WRITE)
            } catch(e:Exception) { throw IllegalStateException("RUNTIME_CREDENTIAL_CREATION_FAILED") }
        }
        requireJob(Files.isRegularFile(settingsFile,LinkOption.NOFOLLOW_LINKS) && Files.isRegularFile(secretsFile,LinkOption.NOFOLLOW_LINKS),"UNSAFE_RUNTIME_FILE")
        val settings=Json.parseToJsonElement(Files.readString(settingsFile)).jsonObject
        val secrets=Json.parseToJsonElement(Files.readString(secretsFile)).jsonObject
        requireJob(settings["schemaVersion"]?.jsonPrimitive?.intOrNull==1,"RUNTIME_SCHEMA_UNSUPPORTED")
        fun local(value:String):Path {
            val path=Path.of(value)
            val resolved=(if(path.isAbsolute) path else directory.resolve(path)).toAbsolutePath().normalize()
            requireJob(resolved.startsWith(directory) && !Files.isSymbolicLink(resolved),"RUNTIME_PATH_OUTSIDE_INSTALLATION")
            return resolved
        }
        val store=local(settings["workerStore"]?.jsonPrimitive?.content ?: "worker-store")
        val roots=(settings["inputRoots"] as? JsonArray).orEmpty().map { local(it.jsonPrimitive.content) }
        roots.forEach { Files.createDirectories(it) }
        val values=mapOf("BURP_DIAG_MANAGED" to "1","BURP_DIAG_WORKER_TOKEN" to secrets.getValue("worker").jsonPrimitive.content,
            "BURP_DIAG_CPH_TOKEN" to secrets.getValue("cph").jsonPrimitive.content,"BURP_DIAG_STORE" to store.toString(),
            "BURP_DIAG_VERIFIED_CAPABILITIES" to (settings["verifiedCapabilities"] as? JsonArray).orEmpty().joinToString(",") { it.jsonPrimitive.content })
        val mode=settings["authorizationMode"]?.jsonPrimitive?.content ?: defaultAuthorizationMode()
        return ManagedSettings.environment(values+("BURP_DIAG_AUTHORIZATION_MODE" to mode)).copy(inputRoots=roots,secretGenerationsFile=settings["secretGenerationsFile"]?.jsonPrimitive?.contentOrNull?.let(::local),profileFile=settingsFile)
    }
}
