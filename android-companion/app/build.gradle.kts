plugins {
    id("com.android.application")
}

android {
    namespace = "com.bolt12pay.companion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.bolt12pay.companion"
        minSdk = 26
        targetSdk = 36
        versionCode = 9
        versionName = "0.1.8-dev"

        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
