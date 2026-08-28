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
    "gate-check",
)
