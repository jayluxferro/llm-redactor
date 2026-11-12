plugins {
    kotlin("jvm") version "2.1.0"
    id("com.gradleup.shadow") version "8.3.5"
}

group = "org.llmredactor"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2")
    implementation("com.github.luben:zstd-jni:1.5.7-4")
    testImplementation(kotlin("test"))
}

// Java 17 bytecode (Burp's minimum) from whatever JDK runs Gradle (>= 17).
// jvmToolchain(17) demanded an installed JDK 17 exactly, so the build failed
// on machines and CI images that only carry 21.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

// The seed-phrase wordlists are the Python package's own files, SHA-256 pinned
// by tests/test_detect_wallets.py: one copy in the repository, not two.
tasks.processResources {
    from("../src/llm_redactor/detect/wordlists") {
        into("org/llmredactor/burp/wordlists")
    }
}

tasks.test { useJUnitPlatform() }

tasks.shadowJar {
    archiveBaseName.set("burp-llm-redactor")
    archiveVersion.set("")
    archiveClassifier.set("")
}
