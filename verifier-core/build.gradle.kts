plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
    jacoco
    `java-test-fixtures`
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    api(libs.nimbus.jose.jwt)
    api(libs.kotlinx.serialization.json)
    implementation(libs.eudi.sdjwt)
    implementation(libs.kotlinx.coroutines.core)
    testFixturesImplementation(libs.eudi.sdjwt)
    testFixturesImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

// Line coverage of this module must stay >= 90%: it is the module that decides whether
// a credential is accepted.
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.90".toBigDecimal()
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}
