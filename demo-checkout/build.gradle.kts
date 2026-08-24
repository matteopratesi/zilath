plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":verifier-spring-boot-starter"))
    implementation(project(":verifier-trust-itwallet"))
    implementation(libs.spring.boot.starter.web)
    // Nimbus needs BouncyCastle to parse PEM key material (demo-only dependency).
    runtimeOnly(libs.bcpkix)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
