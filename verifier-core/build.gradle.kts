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
    // The EUDI SD-JWT library declares a whole ktor HTTP client stack (27 io.ktor modules)
    // in compile scope, for network helpers Zilath never calls: no engine is on the
    // classpath and no Zilath code references it. Excluded so that integrators do not ship,
    // patch and answer scanners for code that never runs; the exclusion is written into the
    // published POM, and `checkPublishedRuntimeClasspath` fails the build if it ever comes back.
    implementation(libs.eudi.sdjwt) { exclude(group = "io.ktor") }
    implementation(libs.kotlinx.coroutines.core)
    testFixturesImplementation(libs.eudi.sdjwt) { exclude(group = "io.ktor") }
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
