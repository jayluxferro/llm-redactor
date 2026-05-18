plugins {
    kotlin("jvm") version "2.1.20"
    id("com.gradleup.shadow") version "9.0.0-beta9"
}

group = "com.llmredactor"
version = "1.0.0"

// Use whatever JDK is on PATH; target bytecode compatible with Java 17+.
kotlin {
    jvmToolchain(21)
}
java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    // Montoya API — provided by Burp at runtime, do NOT bundle.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")

    // Kotlin stdlib — must be bundled (Burp does not provide it).
    implementation(kotlin("stdlib"))

    // Minimal JSON library: 67 KB, zero transitive dependencies.
    implementation("org.json:json:20240303")
    implementation("com.aayushatharva.brotli4j:brotli4j:1.17.0")
    implementation("com.github.luben:zstd-jni:1.5.6-3")
    implementation("org.apache.commons:commons-compress:1.27.1")
    brotliNativeArtifacts().forEach { artifact ->
        runtimeOnly("com.aayushatharva.brotli4j:$artifact:1.17.0")
    }

    testImplementation(kotlin("test"))
    testImplementation("io.mockk:mockk:1.14.4")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    archiveFileName.set("burp-llm-redactor.jar")
    // Relocate kotlin stdlib to avoid conflicts with other Burp extensions.
    relocate("kotlin", "com.llmredactor.shadow.kotlin")
    relocate("com.aayushatharva.brotli4j", "com.llmredactor.shadow.brotli4j")
    relocate("com.github.luben.zstd", "com.llmredactor.shadow.zstd")
    relocate("org.apache.commons.compress", "com.llmredactor.shadow.compress")
    mergeServiceFiles()
}

// Make the default build artifact the fat jar.
tasks.build {
    dependsOn(tasks.shadowJar)
}

fun brotliNativeArtifacts(): List<String> = listOf(
    "native-linux-x86_64",
    "native-linux-aarch64",
    "native-osx-x86_64",
    "native-osx-aarch64",
    "native-windows-x86_64",
)
