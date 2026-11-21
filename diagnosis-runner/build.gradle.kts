plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    application
}
kotlin { jvmToolchain(21) }
dependencies {
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    api(project(":diagnosis-contract"))
    implementation(libs.kotlin.stdlib)
    implementation("org.xerial:sqlite-jdbc:3.46.1.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.13.4")
}
application { mainClass.set("net.portswigger.diagnosis.runner.MainKt") }
tasks.test {
    useJUnitPlatform()
    val verificationTemp=rootProject.layout.projectDirectory.dir("../temp/decoupling-verification/jvm-temp").asFile
    systemProperty("java.io.tmpdir",verificationTemp.absolutePath)
    doFirst { verificationTemp.mkdirs() }
}
