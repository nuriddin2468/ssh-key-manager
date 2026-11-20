import javax.inject.Inject
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/** The Cargo workspace: the repository's root, two folders up. */
val cargoWorkspace: Directory = rootProject.layout.projectDirectory.dir("../..")

/** Android ABIs the Rust library is built for (see gradle.properties). */
val rustAbis: List<String> =
    providers.gradleProperty("rustAbis").get().split(',').map(String::trim).filter(String::isNotEmpty)

val minSdkVersion = 29

android {
    namespace = "dev.sshkeymanager.android"
    // Android 17's second minor release, which Compose's libraries need.
    compileSdk {
        version = release(37) { minorApiLevel = 2 }
    }
    // The NDK cargo-ndk links the Rust library with.
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "dev.sshkeymanager.android"
        minSdk = minSdkVersion
        targetSdk = 37
        versionCode = 1
        versionName = "0.11.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Only the ABIs the Rust library exists for, so JNA's other native
        // parts stay out of the APK.
        ndk { abiFilters += rustAbis }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    androidResources {
        // The languages in Android's per-app language settings, from the
        // `values-*` folders (res/resources.properties names the default).
        generateLocaleConfig = true
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        // These compare with the newest releases online, so the result would
        // change from one day to the next; versions are bumped on purpose.
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
        // It can't read the ABI list from gradle.properties, which has x86_64.
        disable += "ChromeOsAbiSupport"
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.jna) {
        artifact { type = "aar" }
    }
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit)

    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.compose.ui.test.junit4)
}

// --- The Rust core -----------------------------------------------------------
//
// `crates/sshkm-mobile` is built for each ABI with cargo-ndk, and UniFFI's
// generator writes the Kotlin bindings from the built library. Both are
// generated sources of each variant: debug builds Cargo's dev profile, release
// its release profile.

/** Cargo from `-Pcargo`, `$CARGO`, rustup's usual place, or the PATH. */
fun cargoExecutable(): String =
    providers.gradleProperty("cargo").orNull
        ?: providers.environmentVariable("CARGO").orNull
        ?: File(System.getProperty("user.home"), ".cargo/bin/cargo").takeIf(File::canExecute)?.path
        ?: "cargo"

/** What the Rust library is built from, so Gradle knows when to build it again. */
fun rustSources(task: Task): ConfigurableFileCollection =
    task.project.files(
        cargoWorkspace.dir("crates/sshkm-core"),
        cargoWorkspace.dir("crates/sshkm-mobile"),
        cargoWorkspace.file("Cargo.toml"),
        cargoWorkspace.file("Cargo.lock"),
        cargoWorkspace.file("rust-toolchain.toml"),
    )

abstract class CargoNdkBuild : DefaultTask() {
    @get:Inject abstract val exec: ExecOperations

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input abstract val cargo: Property<String>
    @get:Input abstract val abis: ListProperty<String>
    @get:Input abstract val platform: Property<Int>
    @get:Input abstract val release: Property<Boolean>

    @get:Internal abstract val workspace: DirectoryProperty
    @get:Internal abstract val ndk: DirectoryProperty

    /** `<abi>/libsshkm_mobile.so`, as `jniLibs` expects. */
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        exec.exec {
            workingDir = workspace.get().asFile
            environment("ANDROID_NDK_HOME", ndk.get().asFile.path)
            // Backtraces keep file and line; the rest of the debug info would
            // make the library some 200 MB before it is stripped.
            environment("CARGO_PROFILE_DEV_DEBUG", "line-tables-only")
            // The release profile strips symbols, and with them the metadata
            // UniFFI writes the bindings from; strip only the debug info here.
            // Packaging strips the library again.
            environment("CARGO_PROFILE_RELEASE_STRIP", "debuginfo")
            val args = mutableListOf(cargo.get(), "ndk")
            abis.get().forEach { args += listOf("-t", it) }
            args += listOf("-P", platform.get().toString(), "-o", out.path, "build", "-p", "sshkm-mobile", "--locked")
            if (release.get()) args += "--release"
            commandLine(args)
        }
    }
}

abstract class UniffiBindings : DefaultTask() {
    @get:Inject abstract val exec: ExecOperations

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val library: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val config: RegularFileProperty

    @get:Input abstract val cargo: Property<String>
    @get:Internal abstract val workspace: DirectoryProperty

    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        exec.exec {
            workingDir = workspace.get().asFile
            commandLine(
                cargo.get(), "run", "--locked", "-q", "-p", "sshkm-mobile", "--features", "bindgen",
                "--bin", "uniffi-bindgen", "--",
                "generate", "--library", library.get().asFile.path,
                "--language", "kotlin", "--no-format", "--out-dir", out.path,
            )
        }
    }
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar(Char::uppercase)
        val rust = tasks.register<CargoNdkBuild>("cargoBuild$name") {
            group = "rust"
            description = "Builds the Rust core for ${variant.name} with cargo-ndk."
            sources.from(rustSources(this))
            cargo = cargoExecutable()
            abis = rustAbis
            platform = minSdkVersion
            release = variant.buildType == "release"
            workspace = cargoWorkspace
            ndk = androidComponents.sdkComponents.ndkDirectory
            outputDir = layout.buildDirectory.dir("rust/${variant.name}/jniLibs")
        }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(rust, CargoNdkBuild::outputDir)

        val bindings = tasks.register<UniffiBindings>("uniffiBindings$name") {
            group = "rust"
            description = "Writes the Kotlin bindings of the Rust core for ${variant.name}."
            library = rust.flatMap { it.outputDir.file("${rustAbis.first()}/libsshkm_mobile.so") }
            config = cargoWorkspace.file("crates/sshkm-mobile/uniffi.toml")
            cargo = cargoExecutable()
            workspace = cargoWorkspace
            outputDir = layout.buildDirectory.dir("rust/${variant.name}/kotlin")
        }
        variant.sources.kotlin?.addGeneratedSourceDirectory(bindings, UniffiBindings::outputDir)
    }
}
