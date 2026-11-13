plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}
kotlin { jvmToolchain(21) }
dependencies {
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    api(libs.kotlinx.serialization.json)
    implementation(libs.kotlin.stdlib)
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
}
tasks.test {
    useJUnitPlatform()
    val verificationTemp=rootProject.layout.projectDirectory.dir("../temp/decoupling-verification/jvm-temp").asFile
    systemProperty("java.io.tmpdir",verificationTemp.absolutePath)
    doFirst { verificationTemp.mkdirs() }
}
