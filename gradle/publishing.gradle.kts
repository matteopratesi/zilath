/*
 * Maven Central publishing for the four library modules.
 *
 * Applied from the root build. Everything here produces artifacts LOCALLY, into a single
 * staging tree under the root build directory; nothing is uploaded by Gradle. Uploading is
 * a deliberate human step, documented in docs/releasing.md — a version pushed to Central
 * can never be deleted or replaced, so it is not something a build task should be able to
 * do by accident.
 */

val publishedModules =
    setOf(
        "verifier-core",
        "verifier-openid4vp",
        "verifier-trust-itwallet",
        "verifier-spring-boot-starter",
    )

/** One-line description per artifact; Maven Central requires a non-empty description. */
val moduleDescriptions =
    mapOf(
        "verifier-core" to
            "Credential verification for OpenID4VP relying parties: SD-JWT VC signature, " +
            "key binding, disclosures and revocation status. Pure JVM, no framework, no network I/O.",
        "verifier-openid4vp" to
            "OpenID4VP relying-party flow: transactions, signed request objects, direct_post " +
            "responses, replay protection and outcome-only verification receipts.",
        "verifier-trust-itwallet" to
            "OpenID Federation trust evaluation for the IT-Wallet profile: trust chain " +
            "validation, entity configuration and metadata_policy resolution.",
        "verifier-spring-boot-starter" to
            "Spring Boot auto-configuration for Zilath: wires the relying-party flow and " +
            "exposes the wallet-facing endpoints from properties.",
    )

/**
 * Root package of each module, published as `Automatic-Module-Name`.
 *
 * Mapped by hand because it is NOT derivable from the module name: `verifier-trust-itwallet`
 * lives in `dev.zilath.verifier.trust`, and `verifier-spring-boot-starter` in
 * `dev.zilath.verifier.spring`. Deriving it would mint module names for packages that do not
 * exist — and once published, the name is a compatibility promise: changing it later breaks
 * every consumer using the Java module system.
 */
val moduleAutomaticNames =
    mapOf(
        "verifier-core" to "dev.zilath.verifier.core",
        "verifier-openid4vp" to "dev.zilath.verifier.openid4vp",
        "verifier-trust-itwallet" to "dev.zilath.verifier.trust",
        "verifier-spring-boot-starter" to "dev.zilath.verifier.spring",
    )

/** Where every module stages its artifacts, so one bundle can carry them all. */
val stagingDir = rootProject.layout.buildDirectory.dir("staging-deploy")

/**
 * The staging tree survives between builds, so without this a bundle would carry whatever
 * earlier releases left behind — and be uploaded to a place where nothing can be taken back.
 * Every publish task depends on it, so it runs once, first.
 */
val cleanStagingRepository =
    tasks.register<Delete>("cleanStagingRepository") {
        description = "Empties the staging tree so a bundle can only contain this release."
        delete(stagingDir)
    }

configure(subprojects.filter { it.name in publishedModules }) {
    apply(plugin = "maven-publish")
    apply(plugin = "signing")
    apply(plugin = "org.jetbrains.dokka")

    // `java-test-fixtures` adds the fixtures as a variant of the java component, so they
    // would be published too. They exist for our own tests, not as a supported API, and an
    // artifact on Central can never be withdrawn: not publishing them is the reversible
    // direction. Hooked on ITS own plugin because verifier-core applies it after Kotlin,
    // so the configurations do not exist yet in the callback below.
    pluginManager.withPlugin("java-test-fixtures") {
        val javaComponent = components["java"] as AdhocComponentWithVariants
        listOf("testFixturesApiElements", "testFixturesRuntimeElements").forEach { name ->
            javaComponent.withVariantsFromConfiguration(configurations[name]) { skip() }
        }
    }

    // Everything below needs the Java/Kotlin plugin, which each module applies during its
    // own evaluation — after this root block runs. Hooking the callback instead of
    // configuring eagerly is what keeps the two orders from mattering.
    pluginManager.withPlugin("org.jetbrains.kotlin.jvm") {
        extensions.configure<JavaPluginExtension> { withSourcesJar() }

        val javaComponent = components["java"] as AdhocComponentWithVariants

        // Central requires a -javadoc.jar. For Kotlin that is Dokka's HTML output: an empty
        // jar would satisfy the rule and betray the point, in a library whose public API was
        // documented on purpose.
        val javadocJar =
            tasks.register<Jar>("javadocJar") {
                archiveClassifier.set("javadoc")
                from(tasks.named("dokkaGeneratePublicationHtml"))
            }

        // AGPL section 4 asks that a copy of the licence travel with the program. Every
        // source file carries the header, but the binary jar is what people actually receive
        // and redistribute, and for a project whose commercial licence rests entirely on the
        // copyleft holding, shipping the artifact without the licence text is the one gap
        // worth not having. It goes in all three: jar, sources and javadoc are all published.
        listOf(tasks.named<Jar>("jar"), tasks.named<Jar>("sourcesJar"), javadocJar).forEach { jarTask ->
            jarTask.configure { metaInf { from(rootProject.file("LICENSE")) } }
        }

        // Nothing about the build machine goes in here — no Built-By, no Build-Jdk, no
        // timestamp: they leak the environment and defeat reproducible builds.
        tasks.named<Jar>("jar") {
            manifest {
                attributes(
                    "Automatic-Module-Name" to
                        (moduleAutomaticNames[project.name] ?: error("no module name for ${project.name}")),
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                )
            }
        }

        extensions.configure<PublishingExtension> {
            repositories {
                maven {
                    name = "staging"
                    url = uri(stagingDir)
                }
            }
            publications {
                create<MavenPublication>("maven") {
                    from(javaComponent)
                    artifact(javadocJar)
                    pom {
                        name.set("Zilath ${project.name}")
                        description.set(
                            moduleDescriptions[project.name]
                                ?: error("no POM description for ${project.name}"),
                        )
                        url.set("https://github.com/matteopratesi/zilath")
                        inceptionYear.set("2026")
                        licenses {
                            license {
                                name.set("GNU Affero General Public License v3.0 or later")
                                url.set("https://www.gnu.org/licenses/agpl-3.0.txt")
                                distribution.set("repo")
                            }
                        }
                        developers {
                            developer {
                                id.set("matteopratesi")
                                name.set("Matteo Pratesi")
                                url.set("https://github.com/matteopratesi")
                            }
                        }
                        scm {
                            connection.set("scm:git:https://github.com/matteopratesi/zilath.git")
                            developerConnection.set("scm:git:ssh://git@github.com/matteopratesi/zilath.git")
                            url.set("https://github.com/matteopratesi/zilath")
                        }
                        issueManagement {
                            system.set("GitHub Issues")
                            url.set("https://github.com/matteopratesi/zilath/issues")
                        }
                    }
                }
            }
        }

        tasks.named("publishMavenPublicationToStagingRepository") {
            dependsOn(cleanStagingRepository)
        }

        extensions.configure<SigningExtension> {
            // Signing is required by Central and irrelevant to everyday development, so the
            // key comes from the environment and its absence disables signing instead of
            // failing the build. The guard in `centralBundle` is what stops an UNSIGNED
            // release bundle from being produced silently.
            val signingKey = providers.environmentVariable("ZILATH_SIGNING_KEY").orNull
            val signingPassword = providers.environmentVariable("ZILATH_SIGNING_PASSWORD").orNull
            if (!signingKey.isNullOrBlank()) {
                useInMemoryPgpKeys(signingKey, signingPassword)
                sign(extensions.getByType<PublishingExtension>().publications["maven"])
            }
        }
    }
}

/**
 * Stages every published module and packs the result into the single zip the Central Portal
 * accepts. Refuses to run for a SNAPSHOT (Central takes releases only) and refuses to
 * produce an unsigned bundle, which would be rejected on upload anyway — better to find out
 * here than after uploading.
 */
tasks.register<Zip>("centralBundle") {
    group = "publishing"
    description = "Builds the signed bundle to upload to the Maven Central Portal."

    dependsOn(
        subprojects
            .filter { it.name in publishedModules }
            .map { "${it.path}:publishMavenPublicationToStagingRepository" },
    )

    doFirst {
        val version = project.subprojects.first { it.name in publishedModules }.version.toString()
        require(!version.endsWith("SNAPSHOT")) {
            "Maven Central accepts releases only; set a non-SNAPSHOT version before bundling (current: $version)"
        }
        require(!providers.environmentVariable("ZILATH_SIGNING_KEY").orNull.isNullOrBlank()) {
            "ZILATH_SIGNING_KEY is not set: the bundle would be unsigned and Central would reject it"
        }
    }

    from(stagingDir)
    // Checksums stay in: Sonatype's requirements say .md5 and .sha1 are REQUIRED for every
    // deployed file, and their documented bundle layout shows them alongside the .asc.
    // What that layout does NOT show is maven-metadata.xml — Central builds its own — so it
    // is the one thing excluded here. If the Portal ever objects, drop this exclusion.
    exclude("**/maven-metadata.xml*")
    archiveFileName.set("zilath-central-bundle.zip")
    destinationDirectory.set(rootProject.layout.buildDirectory.dir("central"))
}
