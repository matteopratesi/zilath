plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.ktlint) apply false
    alias(libs.plugins.detekt) apply false
    alias(libs.plugins.spotless)
}

// AGPL-3.0 license header enforced on every Kotlin source file (plan: docs/03 §1).
spotless {
    kotlin {
        target("*/src/**/*.kt")
        licenseHeaderFile(rootProject.file("config/license-header.txt"))
    }
}
