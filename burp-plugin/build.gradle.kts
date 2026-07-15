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

kotlin { jvmToolchain(17) }

tasks.test { useJUnitPlatform() }

tasks.shadowJar {
    archiveBaseName.set("burp-llm-redactor")
    archiveVersion.set("")
    archiveClassifier.set("")
}
