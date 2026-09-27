// Plugins resolve from the Gradle Plugin Portal, as they always did by default; declared so
// that the repository every plugin comes from is written down next to the one every library
// comes from, both checked against gradle/verification-metadata.xml.
pluginManagement {
    repositories {
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
}

rootProject.name = "zilath"

include(
    "verifier-core",
    "verifier-openid4vp",
    "verifier-trust-itwallet",
    "verifier-spring-boot-starter",
    "demo-checkout",
)
