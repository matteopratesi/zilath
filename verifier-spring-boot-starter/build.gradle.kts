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
    // Spring Security itself, not Spring Boot's security auto-configuration: the README's chain
    // is tested alone, and the other tests keep an unsecured application.
    testImplementation(libs.spring.security.config)
    testImplementation(libs.spring.security.web)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
