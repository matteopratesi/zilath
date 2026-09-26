plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
    // The TransactionStore conformance kit, checking properties 1 to 5 of the store contract.
    // Test fixtures are not published (gradle/publishing.gradle.kts): the kit is in this
    // repository, for integrators to copy into their tests or build from source.
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
    // Writes the certificates an x509_hash relying party signs with.
    testImplementation(libs.bcpkix)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}
