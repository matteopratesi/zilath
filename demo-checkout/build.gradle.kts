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

springBoot {
    mainClass.set("dev.zilath.demo.ConformanceDemoAppKt")
}

dependencies {
    implementation(project(":verifier-spring-boot-starter"))
    implementation(project(":verifier-trust-itwallet"))
    implementation(libs.spring.boot.starter.web)
    implementation(libs.zxing.core)
    // Simulated-CED demo wallet: mints the credential with the same EUDI library.
    implementation(libs.eudi.sdjwt)
    implementation(libs.kotlinx.coroutines.core)
    // Nimbus needs BouncyCastle to parse PEM key material (demo-only dependency).
    runtimeOnly(libs.bcpkix)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.spring.boot.starter.webmvc.test)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("cedWallet") {
    group = "demo"
    description = "Simulated-CED demo wallet (args: init [dir] | run <txId> [baseUrl] [keysDir])"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("dev.zilath.demo.cedsim.DemoWalletSimulator")
    // Relative key paths must resolve against the repository root, not the module dir.
    workingDir = rootDir
}
