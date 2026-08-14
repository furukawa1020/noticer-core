plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.noticer.collector"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.noticer.collector"
        minSdk = 33
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        debug {
            buildConfigField("boolean", "ALLOW_RAW_DEBUG", "false")
        }
        create("lab") {
            initWith(getByName("debug"))
            applicationIdSuffix = ".lab"
            versionNameSuffix = "-lab"
            matchingFallbacks += listOf("debug")
            buildConfigField("boolean", "ALLOW_RAW_DEBUG", "true")
        }
        release {
            isMinifyEnabled = true
            buildConfigField("boolean", "ALLOW_RAW_DEBUG", "false")
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

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.isIncludeAndroidResources = false
    }
}

dependencies {
    implementation("com.github.polarofficial:polar-ble-sdk:8.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    testImplementation("junit:junit:4.13.2")
}

val verifyProductionSurface by tasks.registering {
    group = "verification"
    description = "Reject raw logging and analytics from the collector production source set."
    doLast {
        val forbidden = listOf(
            "android.util.Log",
            "println(",
            "FirebaseAnalytics",
            "Crashlytics",
            "Amplitude",
            "Mixpanel",
        )
        fileTree("src/main") { include("**/*.kt") }.forEach { source ->
            val contents = source.readText(Charsets.UTF_8)
            forbidden.forEach { token ->
                check(token !in contents) { "Forbidden production token '$token' in $source" }
            }
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(verifyProductionSurface)
}

