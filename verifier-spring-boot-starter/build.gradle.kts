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

    // Spring Boot 4.1.1, the latest release, manages Tomcat 11.0.24 and Jackson 3.1.5, which have
    // advisories fixed in later releases. These constraints raise them for whoever resolves the
    // starter through Gradle; they can go once Spring Boot manages fixed versions.
    constraints {
        implementation(libs.tomcat.embed.core) {
            because("11.0.24 has GHSA-9xv2-5v5q-p794, GHSA-gcx9-497g-6cp6 and GHSA-h3x4-894j-xpx5")
        }
        implementation(libs.tomcat.embed.el) {
            because("kept with tomcat-embed-core, whose 11.0.24 has GHSA-9xv2-5v5q-p794 and two more")
        }
        implementation(libs.tomcat.embed.websocket) {
            because("kept with tomcat-embed-core, whose 11.0.24 has GHSA-9xv2-5v5q-p794 and two more")
        }
        implementation(libs.jackson.databind) {
            because(
                "3.1.5 has GHSA-cxp5-3px4-pw24, GHSA-gx83-3vf8-gh7j, GHSA-q4xh-88c3-wmh7, " +
                    "GHSA-wjgm-6hv5-3cvf and GHSA-wv8q-qhhj-9h54",
            )
        }
        implementation(libs.jackson.core) {
            because("3.1.5 has GHSA-7hhh-6rmp-j9qf and GHSA-p6pp-m3f8-5c89")
        }
    }
}

tasks.test {
    useJUnitPlatform()
}
