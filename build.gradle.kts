plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.ktlint) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.dokka) apply false
    alias(libs.plugins.spotless)
}

// Maven coordinates. The groupId is the reverse-DNS form of zilath.dev, a domain the
// project owns: Maven Central verifies namespace ownership through a DNS TXT record on it.
subprojects {
    group = "dev.zilath"
    version = "0.2.0-SNAPSHOT"
}

// Maven Central publishing for the library modules. Produces artifacts
// locally only: the upload is a documented manual step, see docs/releasing.md.
apply(from = rootProject.file("gradle/publishing.gradle.kts"))

// AGPL-3.0 license header enforced on every Kotlin source file.
spotless {
    kotlin {
        target("*/src/**/*.kt")
        licenseHeaderFile(rootProject.file("config/license-header.txt"))
    }
}
