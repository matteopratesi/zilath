plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
    // The TransactionStore conformance kit: integrators extend it to check their own store.
    `java-test-fixtures`
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(project(":verifier-core"))
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.kotlinx.serialization.json)
    testFixturesApi(libs.junit.jupiter)
    testFixturesImplementation(libs.assertj.core)
    testImplementation(testFixtures(project(":verifier-core")))
    // For the issuance DSL of the core test vectors, which the flow tests choose disclosures with.
    testImplementation(libs.eudi.sdjwt) { exclude(group = "io.ktor") }
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
