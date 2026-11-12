plugins {
    java
    application
}

group = "io.github.almeida96"
version = "0.1.0"
repositories { mavenCentral() }

dependencies {
    implementation("org.ow2.asm:asm:9.9")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.4")
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.1.3")
}

java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
application { mainClass = "io.github.almeida96.linkagelens.Main" }
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release = 21
}
tasks.test { useJUnitPlatform() }
dependencyLocking { lockAllConfigurations() }

val fixtures = listOf("legacy", "current", "client").associateWith { name ->
    sourceSets.create(name) {
        java.setSrcDirs(listOf("examples/checkout/$name"))
    }
}
fixtures.getValue("client").compileClasspath = fixtures.getValue("current").output
for ((name, fixture) in fixtures) {
    tasks.named<JavaCompile>(fixture.compileJavaTaskName) { options.release = 8 }
    val archive = tasks.register<Jar>("${name}FixtureJar") {
        from(fixture.output)
        archiveFileName = when (name) {
            "client" -> "checkout.jar"
            else -> "tariff-$name.jar"
        }
        destinationDirectory = layout.buildDirectory.dir("fixture-jars")
    }
    tasks.processResources { from(archive.flatMap { it.archiveFile }) { into("checkout") } }
}

distributions {
    main {
        contents {
            from("README.md", "LICENSE")
            from("examples") { into("examples") }
            from("docs") { into("docs") }
        }
    }
}
