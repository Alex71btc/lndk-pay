import java.util.Properties

plugins {
    id("com.android.application")
}

val releaseSigningPropertiesPath = providers
    .gradleProperty("bolt12PaySigningProperties")
    .orElse(providers.environmentVariable("BOLT12_PAY_SIGNING_PROPERTIES"))
    .orNull
val releaseBuildRequested = gradle.startParameter.taskNames.any {
    it.contains("release", ignoreCase = true)
}

if (releaseBuildRequested && releaseSigningPropertiesPath == null) {
    error(
        "Release signing is required. Set BOLT12_PAY_SIGNING_PROPERTIES or " +
            "-Pbolt12PaySigningProperties to the private signing properties file.",
    )
}

val releaseSigningProperties = Properties()
val releaseSigningFile = releaseSigningPropertiesPath?.let(::file)
if (releaseSigningFile != null) {
    require(releaseSigningFile.isFile) {
        "Release signing properties not found: ${releaseSigningFile.absolutePath}"
    }
    releaseSigningFile.inputStream().use(releaseSigningProperties::load)
}

fun requiredSigningProperty(name: String): String =
    releaseSigningProperties.getProperty(name)?.takeIf(String::isNotBlank)
        ?: error("Missing release signing property: $name")

android {
    namespace = "com.bolt12pay.companion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.bolt12pay.companion"
        minSdk = 26
        targetSdk = 36
        versionCode = 11
        versionName = "1.0.0"

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    signingConfigs {
        if (releaseSigningFile != null) {
            create("release") {
                storeFile = file(requiredSigningProperty("storeFile"))
                storePassword = requiredSigningProperty("storePassword")
                keyAlias = requiredSigningProperty("keyAlias")
                keyPassword = requiredSigningProperty("keyPassword")
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseSigningFile != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
