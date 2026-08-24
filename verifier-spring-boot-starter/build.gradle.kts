plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(project(":verifier-openid4vp"))
    implementation(libs.spring.boot.starter.web)
    // Spring needs kotlin-reflect to bind constructor-based @ConfigurationProperties in Kotlin.
    runtimeOnly(libs.kotlin.reflect)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.starter.webmvc.test)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
